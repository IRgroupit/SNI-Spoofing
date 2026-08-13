from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path

from app_config import AppConfig, ConfigError, UpstreamEndpoint, load_config
from client_allowlist import ClientAllowlist
from connection_limits import ConnectionLimiter
from connection_registry import ConnectionRegistry
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from route_pool import RoutePool, RouteProfile
from utils.network_tools import close_socket, configure_tcp_socket, get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker

LOGGER = logging.getLogger("sni_spoofing")


async def relay_one_way(
    source: socket.socket,
    destination: socket.socket,
    *,
    buffer_size: int,
    idle_timeout: float,
) -> None:
    loop = asyncio.get_running_loop()
    while True:
        data = await asyncio.wait_for(
            loop.sock_recv(source, buffer_size),
            timeout=idle_timeout,
        )
        if not data:
            return
        # sock_sendall returns None on success. The previous code compared it to
        # len(data), which terminated every relay after its first write.
        await asyncio.wait_for(
            loop.sock_sendall(destination, data),
            timeout=idle_timeout,
        )


async def relay_bidirectional(
    first: socket.socket,
    second: socket.socket,
    *,
    buffer_size: int,
    idle_timeout: float,
) -> None:
    tasks = {
        asyncio.create_task(
            relay_one_way(
                first,
                second,
                buffer_size=buffer_size,
                idle_timeout=idle_timeout,
            )
        ),
        asyncio.create_task(
            relay_one_way(
                second,
                first,
                buffer_size=buffer_size,
                idle_timeout=idle_timeout,
            )
        ),
    }
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, (ConnectionError, OSError, TimeoutError)):
            LOGGER.debug("Relay finished: %s", result)
        elif isinstance(result, Exception):
            LOGGER.error("Unexpected relay error: %r", result)


class GatewayServer:
    def __init__(
        self,
        config: AppConfig,
        interface_ipv4: str,
        registry: ConnectionRegistry[FakeInjectiveConnection],
    ) -> None:
        self.config = config
        self.interface_ipv4 = interface_ipv4
        self.registry = registry
        self.client_allowlist = ClientAllowlist(config.allowed_client_cidrs)
        self.limiter = ConnectionLimiter(
            config.max_connections,
            config.max_connections_per_ip,
        )
        self.route_pool = RoutePool(
            config.upstreams,
            config.fake_snis,
            failure_threshold=config.route_failure_threshold,
            cooldown_seconds=config.route_cooldown_seconds,
            max_cooldown_seconds=config.route_max_cooldown_seconds,
            latency_alpha=config.route_latency_alpha,
            exploration_interval=config.route_exploration_interval,
        )
        self.tasks: set[asyncio.Task[None]] = set()
        self.started_at = time.monotonic()
        self.accepted_connections = 0
        self.denied_connections = 0
        self.limit_rejections = 0

    async def _open_route(
        self,
        route: RouteProfile,
    ) -> socket.socket:
        outgoing_sock: socket.socket | None = None
        injective_connection: FakeInjectiveConnection | None = None
        try:
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32),
                os.urandom(32),
                route.fake_sni.encode("ascii"),
                os.urandom(32),
            )

            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            configure_tcp_socket(outgoing_sock)
            outgoing_sock.bind((self.interface_ipv4, 0))
            source_port = outgoing_sock.getsockname()[1]

            injective_connection = FakeInjectiveConnection(
                outgoing_sock,
                self.interface_ipv4,
                route.upstream.ip,
                source_port,
                route.upstream.port,
                fake_data,
                self.config.bypass_method,
            )
            self.registry.add(injective_connection)

            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.sock_connect(
                    outgoing_sock,
                    (route.upstream.ip, route.upstream.port),
                ),
                timeout=self.config.connect_timeout_seconds,
            )
            await asyncio.wait_for(
                injective_connection.t2a_event.wait(),
                timeout=self.config.injection_timeout_seconds,
            )
            if injective_connection.t2a_msg != "fake_data_ack_recv":
                raise ConnectionError(
                    f"Packet injection failed: {injective_connection.t2a_msg or 'no status'}"
                )

            injective_connection.deactivate()
            self.registry.discard(injective_connection.id)
            return outgoing_sock
        except BaseException:
            if injective_connection is not None:
                injective_connection.deactivate()
                self.registry.discard(injective_connection.id)
            close_socket(outgoing_sock)
            raise

    async def handle(
        self,
        incoming_sock: socket.socket,
        remote_address: tuple[str, int],
    ) -> None:
        client_ip = remote_address[0]
        if not self.client_allowlist.allows(client_ip):
            self.denied_connections += 1
            LOGGER.debug("Rejected client outside ALLOWED_CLIENT_CIDRS")
            close_socket(incoming_sock)
            return
        if not self.limiter.try_acquire(client_ip):
            self.limit_rejections += 1
            LOGGER.warning("Connection limit reached for client %s", client_ip)
            close_socket(incoming_sock)
            return
        self.accepted_connections += 1

        outgoing_sock: socket.socket | None = None
        active_route: RouteProfile | None = None
        try:
            configure_tcp_socket(incoming_sock)
            attempted_routes: set[RouteProfile] = set()
            last_route_error: BaseException | None = None
            attempts = min(
                self.config.max_route_attempts,
                self.route_pool.profile_count,
            )
            for attempt in range(1, attempts + 1):
                route = self.route_pool.acquire(attempted_routes)
                if route is None:
                    break
                attempted_routes.add(route)
                active_route = route
                route_started_at = time.monotonic()
                try:
                    outgoing_sock = await self._open_route(route)
                except (ConnectionError, OSError, TimeoutError, ValueError) as exc:
                    last_route_error = exc
                    entered_cooldown = self.route_pool.record_failure(route)
                    self.route_pool.release(route)
                    active_route = None
                    LOGGER.warning(
                        "Route attempt %d/%d failed for %s%s: %s",
                        attempt,
                        attempts,
                        route.label,
                        "; entering cooldown" if entered_cooldown else "",
                        exc,
                    )
                    continue

                self.route_pool.record_success(
                    route,
                    latency_seconds=time.monotonic() - route_started_at,
                )
                LOGGER.debug("Selected route %s after %d attempt(s)", route.label, attempt)
                break

            if outgoing_sock is None:
                raise ConnectionError(
                    f"All route attempts failed: {last_route_error or 'no route available'}"
                )

            await relay_bidirectional(
                incoming_sock,
                outgoing_sock,
                buffer_size=self.config.relay_buffer_size,
                idle_timeout=self.config.idle_timeout_seconds,
            )
        except (ConnectionError, OSError, TimeoutError, ValueError) as exc:
            LOGGER.debug("Connection %s:%s closed: %s", *remote_address, exc)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Unhandled connection error for %s:%s", *remote_address)
        finally:
            if active_route is not None:
                self.route_pool.release(active_route)
            close_socket(outgoing_sock)
            close_socket(incoming_sock)
            self.limiter.release(client_ip)

    async def report_metrics_forever(self) -> None:
        while True:
            await asyncio.sleep(self.config.metrics_interval_seconds)
            route_metrics = []
            for snapshot in self.route_pool.snapshots():
                route_metrics.append(
                    {
                        "route": snapshot.profile.label,
                        "active": snapshot.active,
                        "successes": snapshot.total_successes,
                        "failures": snapshot.total_failures,
                        "consecutive_failures": snapshot.consecutive_failures,
                        "circuit_open_count": snapshot.circuit_open_count,
                        "cooldown_seconds": round(snapshot.cooldown_remaining_seconds, 3),
                        "ewma_latency_ms": (
                            round(snapshot.ewma_latency_ms, 3)
                            if snapshot.ewma_latency_ms is not None
                            else None
                        ),
                    }
                )

            LOGGER.info(
                "gateway_metrics=%s",
                json.dumps(
                    {
                        "uptime_seconds": round(time.monotonic() - self.started_at, 3),
                        "active_connections": self.limiter.active,
                        "accepted_connections": self.accepted_connections,
                        "denied_connections": self.denied_connections,
                        "limit_rejections": self.limit_rejections,
                        "routes": route_metrics,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )

    async def serve_forever(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setblocking(False)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.config.listen_host, self.config.listen_port))
        listener.listen(self.config.listen_backlog)

        LOGGER.info(
            "Listening on %s:%d with %d adaptive routes via %s",
            self.config.listen_host,
            self.config.listen_port,
            self.route_pool.profile_count,
            self.interface_ipv4,
        )
        if self.config.listen_host == "0.0.0.0":
            LOGGER.warning(
                "Public listener enabled; restrict port %d with a firewall to trusted clients",
                self.config.listen_port,
            )
        if self.client_allowlist.allows_all:
            LOGGER.warning(
                "ALLOWED_CLIENT_CIDRS permits every IPv4 address; this listener has no client "
                "authentication"
            )

        loop = asyncio.get_running_loop()
        metrics_task: asyncio.Task[None] | None = None
        if self.config.metrics_interval_seconds > 0:
            metrics_task = asyncio.create_task(
                self.report_metrics_forever(),
                name="route-metrics",
            )
        try:
            while True:
                incoming_sock, remote_address = await loop.sock_accept(listener)
                incoming_sock.setblocking(False)
                task = asyncio.create_task(self.handle(incoming_sock, remote_address))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
        finally:
            close_socket(listener)
            active_tasks = tuple(self.tasks)
            for task in active_tasks:
                task.cancel()
            await asyncio.gather(*active_tasks, return_exceptions=True)
            if metrics_task is not None:
                metrics_task.cancel()
                await asyncio.gather(metrics_task, return_exceptions=True)


def get_executable_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def build_windivert_filter(
    interface_ipv4: str,
    upstreams: tuple[UpstreamEndpoint, ...],
) -> str:
    route_filters = []
    for upstream in dict.fromkeys(upstreams):
        route_filters.append(
            "((ip.SrcAddr == "
            f"{interface_ipv4} and ip.DstAddr == {upstream.ip} and "
            f"tcp.DstPort == {upstream.port}) or "
            f"(ip.SrcAddr == {upstream.ip} and ip.DstAddr == {interface_ipv4} and "
            f"tcp.SrcPort == {upstream.port}))"
        )
    return f"tcp and ({' or '.join(route_filters)})"


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def run() -> int:
    try:
        config = load_config(get_executable_directory() / "config.json")
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.log_level)
    interface_ipv4 = get_default_interface_ipv4(
        config.connect_ip,
        config.connect_port,
    )
    if not interface_ipv4:
        LOGGER.critical("Could not determine the outbound IPv4 interface")
        return 1

    registry: ConnectionRegistry[FakeInjectiveConnection] = ConnectionRegistry()
    injector = FakeTcpInjector(
        build_windivert_filter(interface_ipv4, config.upstreams),
        registry,
    )
    injector_thread = threading.Thread(
        target=injector.run,
        name="windivert-injector",
        daemon=True,
    )
    injector_thread.start()
    if not injector.ready.wait(timeout=5.0):
        LOGGER.critical("WinDivert injector did not start within 5 seconds")
        return 1
    if injector.startup_error is not None:
        LOGGER.critical(
            "WinDivert could not start; run as Administrator and verify the driver: %s",
            injector.startup_error,
        )
        return 1

    server = GatewayServer(config, interface_ipv4, registry)
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
