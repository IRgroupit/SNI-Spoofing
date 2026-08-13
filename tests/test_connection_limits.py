from __future__ import annotations

import unittest

from connection_limits import ConnectionLimiter


class ConnectionLimiterTests(unittest.TestCase):
    def test_enforces_per_ip_limit_and_recovers_after_release(self) -> None:
        limiter = ConnectionLimiter(maximum=3, maximum_per_ip=2)

        self.assertTrue(limiter.try_acquire("192.0.2.1"))
        self.assertTrue(limiter.try_acquire("192.0.2.1"))
        self.assertFalse(limiter.try_acquire("192.0.2.1"))
        self.assertEqual(limiter.active, 2)

        limiter.release("192.0.2.1")

        self.assertTrue(limiter.try_acquire("192.0.2.1"))
        self.assertEqual(limiter.active, 2)

    def test_release_is_idempotent_for_unknown_client(self) -> None:
        limiter = ConnectionLimiter(maximum=2, maximum_per_ip=1)

        limiter.release("198.51.100.9")

        self.assertEqual(limiter.active, 0)


if __name__ == "__main__":
    unittest.main()
