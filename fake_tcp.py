from __future__ import annotations

import asyncio
import heapq
import itertools
import logging
import socket
import threading
import time
from collections.abc import Callable

from pydivert import Packet

from connection_registry import ConnectionRegistry
from injecter import TcpInjector
from monitor_connection import MonitorConnection
from utils.network_tools import close_socket

LOGGER = logging.getLogger(__name__)


class FakeInjectiveConnection(MonitorConnection):
    def __init__(
        self,
        sock: socket.socket,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        fake_data: bytes,
        bypass_method: str,
    ) -> None:
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.running_loop = asyncio.get_running_loop()

    def signal_asyncio(self, message: str) -> None:
        self.t2a_msg = message
        self.running_loop.call_soon_threadsafe(self.t2a_event.set)


class DelayedPacketSender:
    """One scheduler thread replaces an unbounded thread-per-connection model."""

    def __init__(
        self,
        callback: Callable[[Packet, FakeInjectiveConnection], None],
    ) -> None:
        self._callback = callback
        self._condition = threading.Condition()
        self._queue: list[tuple[float, int, Packet, FakeInjectiveConnection]] = []
        self._sequence = itertools.count()
        self._thread = threading.Thread(
            target=self._run,
            name="fake-packet-scheduler",
            daemon=True,
        )
        self._thread.start()

    def schedule(
        self,
        packet: Packet,
        connection: FakeInjectiveConnection,
        delay_seconds: float = 0.001,
    ) -> None:
        deadline = time.monotonic() + delay_seconds
        with self._condition:
            heapq.heappush(
                self._queue,
                (deadline, next(self._sequence), packet, connection),
            )
            self._condition.notify()

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._queue:
                    self._condition.wait()
                deadline, _, packet, connection = self._queue[0]
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                heapq.heappop(self._queue)

            try:
                self._callback(packet, connection)
            except Exception:
                LOGGER.exception("Delayed fake packet callback failed")


class FakeTcpInjector(TcpInjector):
    def __init__(
        self,
        w_filter: str,
        connections: ConnectionRegistry[FakeInjectiveConnection],
    ) -> None:
        super().__init__(w_filter)
        self.connections = connections
        self._delayed_sender = DelayedPacketSender(self._send_fake_packet)

    def _send_fake_packet(
        self,
        packet: Packet,
        connection: FakeInjectiveConnection,
    ) -> None:
        with connection.thread_lock:
            if not connection.monitor:
                return
            if connection.bypass_method != "wrong_seq":
                self._fail_connection(connection, "unsupported_bypass_method")
                return

            packet.tcp.psh = True
            packet.ip.packet_len += len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
            packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF

            try:
                self.w.send(packet, True)
            except Exception:
                LOGGER.exception("Failed to send fake packet for %s", connection.id)
                self._fail_connection(connection, "fake_packet_send_failed")
                return
            connection.fake_sent = True

    def _fail_connection(
        self,
        connection: FakeInjectiveConnection,
        reason: str,
    ) -> None:
        connection.monitor = False
        close_socket(connection.sock)
        connection.signal_asyncio(reason)

    def _on_unexpected_packet(
        self,
        packet: Packet,
        connection: FakeInjectiveConnection,
        reason: str,
    ) -> None:
        LOGGER.debug("Unexpected packet for %s: %s", connection.id, reason)
        self._fail_connection(connection, "unexpected_packet")
        self.w.send(packet, False)

    def _on_inbound_packet(
        self,
        packet: Packet,
        connection: FakeInjectiveConnection,
    ) -> None:
        if connection.syn_seq == -1:
            self._on_unexpected_packet(packet, connection, "SYN not observed")
            return

        payload_is_empty = len(packet.tcp.payload) == 0
        if (
            packet.tcp.ack
            and packet.tcp.syn
            and not packet.tcp.rst
            and not packet.tcp.fin
            and payload_is_empty
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self._on_unexpected_packet(packet, connection, "SYN-ACK sequence changed")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self._on_unexpected_packet(packet, connection, "SYN-ACK did not match SYN")
                return
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return

        if (
            packet.tcp.ack
            and not packet.tcp.syn
            and not packet.tcp.rst
            and not packet.tcp.fin
            and payload_is_empty
            and connection.fake_sent
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            expected_seq = (connection.syn_ack_seq + 1) & 0xFFFFFFFF
            expected_ack = (connection.syn_seq + 1) & 0xFFFFFFFF
            if connection.syn_ack_seq == -1 or seq_num != expected_seq:
                self._on_unexpected_packet(packet, connection, "fake ACK sequence mismatch")
                return
            if ack_num != expected_ack:
                self._on_unexpected_packet(packet, connection, "fake ACK number mismatch")
                return

            connection.monitor = False
            connection.signal_asyncio("fake_data_ack_recv")
            return

        self._on_unexpected_packet(packet, connection, "unexpected inbound state")

    def _on_outbound_packet(
        self,
        packet: Packet,
        connection: FakeInjectiveConnection,
    ) -> None:
        if connection.sch_fake_sent:
            self._on_unexpected_packet(packet, connection, "packet arrived after fake schedule")
            return

        payload_is_empty = len(packet.tcp.payload) == 0
        if (
            packet.tcp.syn
            and not packet.tcp.ack
            and not packet.tcp.rst
            and not packet.tcp.fin
            and payload_is_empty
        ):
            seq_num = packet.tcp.seq_num
            if packet.tcp.ack_num != 0:
                self._on_unexpected_packet(packet, connection, "SYN has a non-zero ACK")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self._on_unexpected_packet(packet, connection, "SYN sequence changed")
                return
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return

        if (
            packet.tcp.ack
            and not packet.tcp.syn
            and not packet.tcp.rst
            and not packet.tcp.fin
            and payload_is_empty
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            expected_seq = (connection.syn_seq + 1) & 0xFFFFFFFF
            expected_ack = (connection.syn_ack_seq + 1) & 0xFFFFFFFF
            if connection.syn_seq == -1 or seq_num != expected_seq:
                self._on_unexpected_packet(packet, connection, "handshake ACK sequence mismatch")
                return
            if connection.syn_ack_seq == -1 or ack_num != expected_ack:
                self._on_unexpected_packet(packet, connection, "handshake ACK number mismatch")
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            self._delayed_sender.schedule(packet, connection)
            return

        self._on_unexpected_packet(packet, connection, "unexpected outbound state")

    def inject(self, packet: Packet) -> None:
        if packet.is_inbound:
            connection_id = (
                packet.ip.dst_addr,
                packet.tcp.dst_port,
                packet.ip.src_addr,
                packet.tcp.src_port,
            )
        elif packet.is_outbound:
            connection_id = (
                packet.ip.src_addr,
                packet.tcp.src_port,
                packet.ip.dst_addr,
                packet.tcp.dst_port,
            )
        else:
            LOGGER.warning("Packet has no inbound/outbound direction; passing through")
            self.w.send(packet, False)
            return

        connection = self.connections.get(connection_id)
        if connection is None:
            self.w.send(packet, False)
            return

        with connection.thread_lock:
            if not connection.monitor:
                self.w.send(packet, False)
            elif packet.is_inbound:
                self._on_inbound_packet(packet, connection)
            else:
                self._on_outbound_packet(packet, connection)
