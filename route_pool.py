from __future__ import annotations

import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass

from app_config import UpstreamEndpoint


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


@dataclass(slots=True)
class _RouteState:
    active: int = 0
    consecutive_failures: int = 0
    total_successes: int = 0
    total_failures: int = 0
    cooldown_until: float = 0.0


class RoutePool:
    """Least-loaded route selection with passive health and circuit breaking."""

    def __init__(
        self,
        upstreams: tuple[UpstreamEndpoint, ...],
        fake_snis: tuple[str, ...],
        *,
        failure_threshold: int,
        cooldown_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not upstreams:
            raise ValueError("upstreams must not be empty")
        if not fake_snis:
            raise ValueError("fake_snis must not be empty")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        if cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be positive")

        self._profiles = tuple(
            RouteProfile(upstream, fake_sni) for upstream in upstreams for fake_sni in fake_snis
        )
        self._states = {profile: _RouteState() for profile in self._profiles}
        self._index = {profile: index for index, profile in enumerate(self._profiles)}
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._cursor = 0
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
            if ready_indexes:
                candidate_indexes = ready_indexes
            else:
                earliest = min(
                    self._states[self._profiles[index]].cooldown_until
                    for index in candidate_indexes
                )
                candidate_indexes = [
                    index
                    for index in candidate_indexes
                    if self._states[self._profiles[index]].cooldown_until == earliest
                ]

            minimum_active = min(
                self._states[self._profiles[index]].active for index in candidate_indexes
            )
            least_loaded = {
                index
                for index in candidate_indexes
                if self._states[self._profiles[index]].active == minimum_active
            }
            selected_index = next(
                index for index in self._round_robin_indexes() if index in least_loaded
            )
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

    def record_success(self, profile: RouteProfile) -> None:
        with self._lock:
            state = self._state(profile)
            state.consecutive_failures = 0
            state.cooldown_until = 0.0
            state.total_successes += 1

    def record_failure(self, profile: RouteProfile) -> bool:
        """Record a failure and return True when the circuit enters cooldown."""

        with self._lock:
            state = self._state(profile)
            state.consecutive_failures += 1
            state.total_failures += 1
            if state.consecutive_failures < self._failure_threshold:
                return False
            state.consecutive_failures = 0
            state.cooldown_until = self._clock() + self._cooldown_seconds
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
                )
                for profile, state in self._states.items()
            )

    def _round_robin_indexes(self) -> tuple[int, ...]:
        return tuple(range(self._cursor, len(self._profiles))) + tuple(range(self._cursor))

    def _state(self, profile: RouteProfile) -> _RouteState:
        try:
            return self._states[profile]
        except KeyError as exc:
            raise ValueError(f"Unknown route profile: {profile.label}") from exc
