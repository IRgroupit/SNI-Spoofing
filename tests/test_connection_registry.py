from __future__ import annotations

import unittest
from dataclasses import dataclass

from connection_registry import ConnectionRegistry


@dataclass
class DummyConnection:
    id: tuple[str, int, str, int]


class ConnectionRegistryTests(unittest.TestCase):
    def test_add_get_and_discard(self) -> None:
        registry: ConnectionRegistry[DummyConnection] = ConnectionRegistry()
        connection = DummyConnection(("192.0.2.1", 40000, "198.51.100.1", 443))

        registry.add(connection)

        self.assertIs(registry.get(connection.id), connection)
        self.assertEqual(len(registry), 1)
        self.assertIs(registry.discard(connection.id), connection)
        self.assertIsNone(registry.get(connection.id))

    def test_duplicate_id_is_rejected(self) -> None:
        registry: ConnectionRegistry[DummyConnection] = ConnectionRegistry()
        connection = DummyConnection(("192.0.2.1", 40000, "198.51.100.1", 443))
        registry.add(connection)

        with self.assertRaises(KeyError):
            registry.add(connection)


if __name__ == "__main__":
    unittest.main()
