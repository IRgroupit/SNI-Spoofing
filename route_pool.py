from __future__ import annotations

import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass

from app_config import RouteConfig, UpstreamEndpoint


@dataclass(frozen=True, slots=True)
class RouteProfile:
    upstream: UpstreamEndpoint
    fake_sni: str

    @property
    def label(self) -> str:
        return f"{self.upstream.label} via {self.fake_sni}"


@dataclass(frozen=True, slots=True)
class RouteSnapshot:
    profile: RouteProfile
    active: int
    consecutive_failures: int
    total_successes: int
    total_failures: int
    cooldown_remaining_seconds: float
    ewma_latency_ms: float | None
    circuit_open_count: int


@dataclass(slots=True)
class _RouteState:
    active: int = 0
    consecutive_failures: int = 0
    total_successes: int = 0
    total_failures: int = 0
    cooldown_until: float = 0.0
    ewma_latency_ms: float | None = None
    circuit_open_count: int = 0


class RoutePool:
    """Latency-aware route selection with passive health and circuit breaking."""

    def __init__(
        self,
        routes: tuple[RouteConfig, ...],
        *,
        failure_threshold: int,
        cooldown_seconds: float,
        max_cooldown_seconds: float,
        latency_alpha: float,
        exploration_interval: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not routes:
            raise ValueError("routes must not be empty")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        if cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be positive")
        if max_cooldown_seconds < cooldown_seconds:
            raise ValueError("max_cooldown_seconds must be at least cooldown_seconds")
        if not 0 < latency_alpha <= 1:
            raise ValueError("latency_alpha must be between 0 and 1")
        if exploration_interval < 2:
            raise ValueError("exploration_interval must be at least 2")

        self._profiles = tuple(RouteProfile(route.upstream, route.fake_sni) for route in routes)
        if len(set(self._profiles)) != len(self._profiles):
            raise ValueError("routes must not contain duplicate route profiles")
        self._states = {profile: _RouteState() for profile in self._profiles}
        self._index = {profile: index for index, profile in enumerate(self._profiles)}
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._max_cooldown_seconds = max_cooldown_seconds
        self._latency_alpha = latency_alpha
        self._exploration_interval = exploration_interval
        self._clock = clock
        self._cursor = 0
        self._selection_count = 0
        self._lock = threading.Lock()

    @property
    def profile_count(self) -> int:
        return len(self._profiles)

    def acquire(
        self,
        excluded: Collection[RouteProfile] = (),
    ) -> RouteProfile | None:
        excluded_set = set(excluded)
        with self._lock:
            candidate_indexes = [
                index for index, profile in enumerate(self._profiles) if profile not in excluded_set
            ]
            if not candidate_indexes:
                return None

            now = self._clock()
            ready_indexes = [
                index
                for index in candidate_indexes
                if self._states[self._profiles[index]].cooldown_until <= now
            ]
            if not ready_indexes:
                return None

            self._selection_count += 1
            selected_index = self._select_index(ready_indexes)
            profile = self._profiles[selected_index]
            self._states[profile].active += 1
            self._cursor = (selected_index + 1) % len(self._profiles)
            return profile

    def release(self, profile: RouteProfile) -> None:
        with self._lock:
            state = self._state(profile)
            if state.active == 0:
                return
            state.active -= 1

    def record_success(
        self,
        profile: RouteProfile,
        latency_seconds: float | None = None,
    ) -> None:
        if latency_seconds is not None and latency_seconds < 0:
            raise ValueError("latency_seconds must not be negative")
        with self._lock:
            state = self._state(profile)
            state.consecutive_failures = 0
            state.cooldown_until = 0.0
            state.circuit_open_count = 0
            state.total_successes += 1
            if latency_seconds is not None:
                sample_ms = latency_seconds * 1000.0
                if state.ewma_latency_ms is None:
                    state.ewma_latency_ms = sample_ms
                else:
                    state.ewma_latency_ms = (
                        self._latency_alpha * sample_ms
                        + (1.0 - self._latency_alpha) * state.ewma_latency_ms
                    )

    def record_failure(self, profile: RouteProfile) -> bool:
        """Record a failure and return True when the circuit enters cooldown."""

        with self._lock:
            state = self._state(profile)
            state.consecutive_failures += 1
            state.total_failures += 1
            now = self._clock()
            if state.cooldown_until > now:
                state.consecutive_failures = 0
                return False

            failure_threshold = 1 if state.circuit_open_count else self._failure_threshold
            if state.consecutive_failures < failure_threshold:
                return False
            state.consecutive_failures = 0
            cooldown_seconds = min(
                self._cooldown_seconds * (2**state.circuit_open_count),
                self._max_cooldown_seconds,
            )
            state.circuit_open_count += 1
            state.cooldown_until = now + cooldown_seconds
            return True

    def snapshots(self) -> tuple[RouteSnapshot, ...]:
        with self._lock:
            now = self._clock()
            return tuple(
                RouteSnapshot(
                    profile=profile,
                    active=state.active,
                    consecutive_failures=state.consecutive_failures,
                    total_successes=state.total_successes,
                    total_failures=state.total_failures,
                    cooldown_remaining_seconds=max(0.0, state.cooldown_until - now),
                    ewma_latency_ms=state.ewma_latency_ms,
                    circuit_open_count=state.circuit_open_count,
                )
                for profile, state in self._states.items()
            )

    def _round_robin_indexes(self) -> tuple[int, ...]:
        return tuple(range(self._cursor, len(self._profiles))) + tuple(range(self._cursor))

    def _select_index(self, candidate_indexes: list[int]) -> int:
        unprobed = {
            index
            for index in candidate_indexes
            if (
                self._states[self._profiles[index]].total_successes
                + self._states[self._profiles[index]].total_failures
                == 0
            )
        }
        if unprobed:
            return next(index for index in self._round_robin_indexes() if index in unprobed)

        if self._selection_count % self._exploration_interval == 0:
            candidates = set(candidate_indexes)
            return next(index for index in self._round_robin_indexes() if index in candidates)

        scores = {
            index: self._selection_score(self._states[self._profiles[index]])
            for index in candidate_indexes
        }
        minimum_score = min(scores.values())
        best = {index for index, score in scores.items() if score == minimum_score}
        return next(index for index in self._round_robin_indexes() if index in best)

    @staticmethod
    def _selection_score(state: _RouteState) -> float:
        latency_ms = state.ewma_latency_ms if state.ewma_latency_ms is not None else 1000.0
        attempts = state.total_successes + state.total_failures
        failure_rate = (state.total_failures + 1) / (attempts + 2)
        reliability_multiplier = 1.0 + 4.0 * failure_rate
        failure_streak_multiplier = 1.0 + state.consecutive_failures
        return (state.active + 1) * latency_ms * reliability_multiplier * failure_streak_multiplier

    def _state(self, profile: RouteProfile) -> _RouteState:
        try:
            return self._states[profile]
        except KeyError as exc:
            raise ValueError(f"Unknown route profile: {profile.label}") from exc
