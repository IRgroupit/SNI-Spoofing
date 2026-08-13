from __future__ import annotations

import threading
from collections import defaultdict


class ConnectionLimiter:
    """Enforces global and per-client limits without retaining client history."""

    def __init__(self, maximum: int, maximum_per_ip: int) -> None:
        if maximum < 1:
            raise ValueError("maximum must be positive")
        if not 1 <= maximum_per_ip <= maximum:
            raise ValueError("maximum_per_ip must be between 1 and maximum")
        self._maximum = maximum
        self._maximum_per_ip = maximum_per_ip
        self._total = 0
        self._per_ip: defaultdict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def try_acquire(self, client_ip: str) -> bool:
        with self._lock:
            if self._total >= self._maximum:
                return False
            if self._per_ip[client_ip] >= self._maximum_per_ip:
                return False
            self._total += 1
            self._per_ip[client_ip] += 1
            return True

    def release(self, client_ip: str) -> None:
        with self._lock:
            current = self._per_ip.get(client_ip, 0)
            if current == 0:
                return
            if current == 1:
                del self._per_ip[client_ip]
            else:
                self._per_ip[client_ip] = current - 1
            self._total -= 1

    @property
    def active(self) -> int:
        with self._lock:
            return self._total
