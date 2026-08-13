from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from app_config import AppConfig, ConfigError, UpstreamEndpoint, load_config
from client_allowlist import ClientAllowlist
from connection_limits import ConnectionLimiter
from connection_registry import ConnectionRegistry
from route_pool import RoutePool, RouteProfile
from utils.network_tools import close_socket, configure_tcp_socket, get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker

if TYPE_CHECKING:
    from fake_tcp import FakeInjectiveConnection

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


async def drain_tasks(
    tasks: Collection[asyncio.Task[None]],
    grace_seconds: float,
) -> tuple[int, int]:
    """Let active tasks finish, then cancel only the tasks that exceed the grace period."""

    if grace_seconds < 0:
        raise ValueError("grace_seconds must not be negative")

    active_tasks = {task for task in tasks if not task.done()}
    if not active_tasks:
        return 0, 0

    if grace_seconds > 0:
        completed, pending = await asyncio.wait(active_tasks, timeout=grace_seconds)
    else:
        completed, pending = set(), active_tasks

    cancellation_count = sum(task.cancel() for task in pending)
    await asyncio.gather(*active_tasks, return_exceptions=True)
    return len(completed), cancellation_count


class GatewayServer:
    def __init__(
        self,
        config: AppConfig,
        interface_by_upstream: Mapping[UpstreamEndpoint, str],
        registry: ConnectionRegistry[FakeInjectiveConnection],
    ) -> None:
        self.config = config
        self.interface_by_upstream = dict(interface_by_upstream)
        missing_interfaces = tuple(
            upstream
            for upstream in config.upstreams
            if not self.interface_by_upstream.get(upstream)
        )
        if missing_interfaces:
            labels = ", ".join(upstream.label for upstream in missing_interfaces)
            raise ValueError(f"Missing outbound interface for: {labels}")
        self.registry = registry
        self.client_allowlist = ClientAllowlist(config.allowed_client_cidrs)
        self.limiter = ConnectionLimiter(
            config.max_connections,
            config.max_connections_per_ip,
        )
        self.route_pool = RoutePool(
            config.routes,
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
        from fake_tcp import FakeInjectiveConnection

        outgoing_sock: socket.socket | None = None
        injective_connection: FakeInjectiveConnection | None = None
        interface_ipv4 = self.interface_by_upstream[route.upstream]
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
            outgoing_sock.bind((interface_ipv4, 0))
            source_port = outgoing_sock.getsockname()[1]

            injective_connection = FakeInjectiveConnection(
                outgoing_sock,
                interface_ipv4,
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
            "Listening on %s:%d with %d adaptive routes across %d outbound interface(s)",
            self.config.listen_host,
            self.config.listen_port,
            self.route_pool.profile_count,
            len(set(self.interface_by_upstream.values())),
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
            if metrics_task is not None:
                metrics_task.cancel()
                await asyncio.gather(metrics_task, return_exceptions=True)
            active_tasks = tuple(self.tasks)
            if active_tasks:
                LOGGER.info(
                    "Draining %d active connection(s) for up to %.1f seconds",
                    len(active_tasks),
                    self.config.shutdown_grace_seconds,
                )
                completed, cancelled = await drain_tasks(
                    active_tasks,
                    self.config.shutdown_grace_seconds,
                )
                LOGGER.info(
                    "Connection drain finished: completed=%d force_cancelled=%d",
                    completed,
                    cancelled,
                )


async def serve_until_shutdown(
    server: GatewayServer,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Stop accepting on a console signal while allowing the server to drain clients."""

    loop = asyncio.get_running_loop()
    manages_signals = shutdown_event is None
    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    previous_handlers: dict[int, object] = {}

    def request_shutdown(_signum: int, _frame: object) -> None:
        loop.call_soon_threadsafe(shutdown_event.set)

    if manages_signals:
        for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            signal_number = getattr(signal, signal_name, None)
            if signal_number is None or signal_number in previous_handlers:
                continue
            try:
                previous_handlers[signal_number] = signal.getsignal(signal_number)
                signal.signal(signal_number, request_shutdown)
            except (OSError, RuntimeError, ValueError):
                previous_handlers.pop(signal_number, None)

    server_task = asyncio.create_task(server.serve_forever(), name="gateway-server")
    shutdown_task = asyncio.create_task(shutdown_event.wait(), name="shutdown-waiter")
    try:
        done, _ = await asyncio.wait(
            (server_task, shutdown_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if shutdown_task in done and not server_task.done():
            LOGGER.info("Shutdown requested")
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
            return
        await server_task
    except asyncio.CancelledError:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        raise
    finally:
        shutdown_task.cancel()
        await asyncio.gather(shutdown_task, return_exceptions=True)
        for signal_number, previous_handler in previous_handlers.items():
            try:
                signal.signal(signal_number, previous_handler)
            except (OSError, RuntimeError, TypeError, ValueError):
                LOGGER.debug("Could not restore signal handler %s", signal_number)


def get_executable_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resolve_upstream_interfaces(
    upstreams: tuple[UpstreamEndpoint, ...],
    resolver: Callable[[str, int], str] | None = None,
) -> dict[UpstreamEndpoint, str]:
    """Resolve the source IPv4 selected by the OS route table for each endpoint."""

    if not upstreams:
        raise ValueError("upstreams must not be empty")
    if resolver is None:
        resolver = get_default_interface_ipv4

    result: dict[UpstreamEndpoint, str] = {}
    for upstream in dict.fromkeys(upstreams):
        try:
            interface_ipv4 = resolver(upstream.ip, upstream.port)
        except OSError as exc:
            raise RuntimeError(
                f"Could not determine the outbound IPv4 interface for {upstream.label}: {exc}"
            ) from exc
        if not interface_ipv4:
            raise RuntimeError(
                f"Could not determine the outbound IPv4 interface for {upstream.label}"
            )
        result[upstream] = interface_ipv4
    return result


def build_windivert_filter(
    interface_by_upstream: Mapping[UpstreamEndpoint, str],
) -> str:
    if not interface_by_upstream:
        raise ValueError("interface_by_upstream must not be empty")

    route_filters = []
    for upstream, interface_ipv4 in interface_by_upstream.items():
        if not interface_ipv4:
            raise ValueError(f"Missing outbound interface for {upstream.label}")
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


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hardened SNI-Spoofing TCP relay")
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to config.json (default: next to the executable)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and route interfaces without starting WinDivert",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    config_path = args.config or (get_executable_directory() / "config.json")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.log_level)
    try:
        interface_by_upstream = resolve_upstream_interfaces(config.upstreams)
        windivert_filter = build_windivert_filter(interface_by_upstream)
    except (RuntimeError, ValueError) as exc:
        LOGGER.critical("Route validation failed: %s", exc)
        return 1

    if args.check_config:
        print(
            "Configuration OK: "
            f"{len(config.routes)} route(s), "
            f"{len(config.upstreams)} upstream(s), "
            f"{len(set(interface_by_upstream.values()))} outbound interface(s)"
        )
        return 0

    try:
        from fake_tcp import FakeTcpInjector
    except ImportError as exc:
        LOGGER.critical("Runtime dependency unavailable: %s", exc)
        return 1

    registry: ConnectionRegistry[FakeInjectiveConnection] = ConnectionRegistry()
    injector = FakeTcpInjector(
        windivert_filter,
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

    server = GatewayServer(config, interface_by_upstream, registry)
    try:
        asyncio.run(serve_until_shutdown(server))
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested")
    except OSError as exc:
        LOGGER.critical("Gateway stopped: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
