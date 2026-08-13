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

from app_config import UpstreamEndpoint  # noqa: E402
from main import (  # noqa: E402
    build_windivert_filter,
    drain_tasks,
    relay_one_way,
    resolve_upstream_interfaces,
    serve_until_shutdown,
)


class RelayTests(unittest.TestCase):
    def test_windivert_filter_covers_every_upstream_and_port(self) -> None:
        first = UpstreamEndpoint("198.51.100.10", 443)
        second = UpstreamEndpoint("198.51.100.20", 8443)
        result = build_windivert_filter(
            {
                first: "192.0.2.1",
                second: "192.0.2.2",
            }
        )

        self.assertIn("ip.SrcAddr == 192.0.2.1", result)
        self.assertIn("ip.DstAddr == 198.51.100.10", result)
        self.assertIn("tcp.DstPort == 443", result)
        self.assertIn("ip.DstAddr == 192.0.2.2", result)
        self.assertIn("ip.SrcAddr == 198.51.100.20", result)
        self.assertIn("tcp.SrcPort == 8443", result)

    def test_resolves_interface_for_each_unique_upstream(self) -> None:
        first = UpstreamEndpoint("198.51.100.10", 443)
        second = UpstreamEndpoint("198.51.100.20", 8443)
        calls: list[tuple[str, int]] = []

        def resolver(ip: str, port: int) -> str:
            calls.append((ip, port))
            return "192.0.2.1" if port == 443 else "192.0.2.2"

        result = resolve_upstream_interfaces((first, second, first), resolver)

        self.assertEqual(
            result,
            {first: "192.0.2.1", second: "192.0.2.2"},
        )
        self.assertEqual(calls, [(first.ip, first.port), (second.ip, second.port)])

    def test_relay_sends_payload_without_false_incomplete_send(self) -> None:
        asyncio.run(self._exercise_relay())

    def test_drain_tasks_cancels_only_after_grace_period(self) -> None:
        asyncio.run(self._exercise_task_drain())

    def test_shutdown_event_cancels_only_the_server_task(self) -> None:
        asyncio.run(self._exercise_shutdown_event())

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

    async def _exercise_task_drain(self) -> None:
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def long_running() -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        task = asyncio.create_task(long_running())
        await started.wait()
        completed_count, cancellation_count = await drain_tasks((task,), 0.0)

        self.assertEqual(completed_count, 0)
        self.assertEqual(cancellation_count, 1)
        self.assertTrue(task.cancelled())
        self.assertTrue(cancelled.is_set())

    async def _exercise_shutdown_event(self) -> None:
        started = asyncio.Event()
        stopped = asyncio.Event()
        shutdown_event = asyncio.Event()

        class FakeServer:
            async def serve_forever(self) -> None:
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()

        runner = asyncio.create_task(serve_until_shutdown(FakeServer(), shutdown_event))
        await started.wait()
        shutdown_event.set()
        await asyncio.wait_for(runner, timeout=1.0)

        self.assertTrue(stopped.is_set())


if __name__ == "__main__":
    unittest.main()
