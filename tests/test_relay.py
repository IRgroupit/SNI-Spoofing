from __future__ import annotations

import asyncio
import socket
import sys
import types
import unittest

if "pydivert" not in sys.modules:
    pydivert_stub = types.ModuleType("pydivert")
    pydivert_stub.Packet = object
    pydivert_stub.WinDivert = object
    sys.modules["pydivert"] = pydivert_stub

from main import relay_one_way  # noqa: E402


class RelayTests(unittest.TestCase):
    def test_relay_sends_payload_without_false_incomplete_send(self) -> None:
        asyncio.run(self._exercise_relay())

    async def _exercise_relay(self) -> None:
        client, relay_source = socket.socketpair()
        relay_destination, upstream = socket.socketpair()
        for sock in (client, relay_source, relay_destination, upstream):
            sock.setblocking(False)

        task = asyncio.create_task(
            relay_one_way(
                relay_source,
                relay_destination,
                buffer_size=4096,
                idle_timeout=1.0,
            )
        )
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendall(client, b"relay-regression-test")
            received = await asyncio.wait_for(loop.sock_recv(upstream, 4096), timeout=1.0)
            self.assertEqual(received, b"relay-regression-test")

            client.close()
            await asyncio.wait_for(task, timeout=1.0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            for sock in (client, relay_source, relay_destination, upstream):
                sock.close()


if __name__ == "__main__":
    unittest.main()
