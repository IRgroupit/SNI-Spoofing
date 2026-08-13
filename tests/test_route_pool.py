from __future__ import annotations

import unittest

from app_config import UpstreamEndpoint
from route_pool import RoutePool


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RoutePoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.pool = RoutePool(
            (
                UpstreamEndpoint("192.0.2.10", 443),
                UpstreamEndpoint("192.0.2.20", 443),
            ),
            ("decoy.example",),
            failure_threshold=2,
            cooldown_seconds=30.0,
            clock=self.clock,
        )

    def test_balances_across_least_loaded_routes(self) -> None:
        first = self.pool.acquire()
        second = self.pool.acquire()

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertNotEqual(first, second)
        self.assertEqual(sum(item.active for item in self.pool.snapshots()), 2)

        self.pool.release(first)
        self.pool.release(second)
        self.assertEqual(sum(item.active for item in self.pool.snapshots()), 0)

    def test_circuit_breaker_skips_failed_route_until_cooldown_expires(self) -> None:
        failed = self.pool.acquire()
        self.assertIsNotNone(failed)
        self.pool.release(failed)

        self.assertFalse(self.pool.record_failure(failed))
        self.assertTrue(self.pool.record_failure(failed))

        selected = self.pool.acquire()
        self.assertNotEqual(selected, failed)
        self.pool.release(selected)

        self.clock.advance(31.0)
        selected_after_cooldown = self.pool.acquire({selected})
        self.assertEqual(selected_after_cooldown, failed)

    def test_success_resets_failure_streak_and_cooldown(self) -> None:
        profile = self.pool.acquire()
        self.assertIsNotNone(profile)
        self.pool.release(profile)

        self.pool.record_failure(profile)
        self.pool.record_success(profile)
        snapshot = next(item for item in self.pool.snapshots() if item.profile == profile)

        self.assertEqual(snapshot.consecutive_failures, 0)
        self.assertEqual(snapshot.cooldown_remaining_seconds, 0.0)
        self.assertEqual(snapshot.total_successes, 1)
        self.assertEqual(snapshot.total_failures, 1)

    def test_excluding_every_route_returns_none(self) -> None:
        profiles = {item.profile for item in self.pool.snapshots()}

        self.assertIsNone(self.pool.acquire(profiles))


if __name__ == "__main__":
    unittest.main()
