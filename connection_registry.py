from __future__ import annotations

import threading
from typing import Generic, Protocol, TypeVar


class IdentifiedConnection(Protocol):
    id: tuple[str, int, str, int]


ConnectionT = TypeVar("ConnectionT", bound=IdentifiedConnection)


class ConnectionRegistry(Generic[ConnectionT]):
    """Small thread-safe registry shared by asyncio and the WinDivert thread."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connections: dict[tuple[str, int, str, int], ConnectionT] = {}

    def add(self, connection: ConnectionT) -> None:
        with self._lock:
            if connection.id in self._connections:
                raise KeyError(f"Duplicate connection id: {connection.id!r}")
            self._connections[connection.id] = connection

    def get(self, connection_id: tuple[str, int, str, int]) -> ConnectionT | None:
        with self._lock:
            return self._connections.get(connection_id)

    def discard(self, connection_id: tuple[str, int, str, int]) -> ConnectionT | None:
        with self._lock:
            return self._connections.pop(connection_id, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._connections)
