from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when config.json contains an unsafe or unsupported value."""


@dataclass(frozen=True, slots=True)
class UpstreamEndpoint:
    ip: str
    port: int

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True, slots=True)
class RouteConfig:
    upstream: UpstreamEndpoint
    fake_sni: str

    @property
    def label(self) -> str:
        return f"{self.upstream.label} via {self.fake_sni}"


@dataclass(frozen=True, slots=True)
class AppConfig:
    listen_host: str
    listen_port: int
    allowed_client_cidrs: tuple[IPv4Network, ...]
    routes: tuple[RouteConfig, ...]
    bypass_method: str
    connect_timeout_seconds: float
    injection_timeout_seconds: float
    idle_timeout_seconds: float
    shutdown_grace_seconds: float
    max_route_attempts: int
    route_failure_threshold: int
    route_cooldown_seconds: float
    route_max_cooldown_seconds: float
    route_latency_alpha: float
    route_exploration_interval: int
    metrics_interval_seconds: float
    relay_buffer_size: int
    max_connections: int
    max_connections_per_ip: int
    listen_backlog: int
    log_level: str

    @property
    def upstreams(self) -> tuple[UpstreamEndpoint, ...]:
        """Return unique endpoints in route declaration order."""

        return tuple(dict.fromkeys(route.upstream for route in self.routes))

    @property
    def fake_snis(self) -> tuple[str, ...]:
        """Compatibility view of unique SNI values in declaration order."""

        return tuple(dict.fromkeys(route.fake_sni for route in self.routes))

    @property
    def connect_ip(self) -> str:
        """Compatibility alias for deployments still using one upstream."""

        return self.upstreams[0].ip

    @property
    def connect_port(self) -> int:
        """Compatibility alias for deployments still using one upstream."""

        return self.upstreams[0].port

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> AppConfig:
        listen_host = _ipv4(raw, "LISTEN_HOST")
        routes = _routes(raw)

        bypass_method = raw.get("BYPASS_METHOD", "wrong_seq")
        if bypass_method != "wrong_seq":
            raise ConfigError("BYPASS_METHOD currently supports only 'wrong_seq'")

        log_level = raw.get("LOG_LEVEL", "INFO")
        if not isinstance(log_level, str) or log_level.upper() not in {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }:
            raise ConfigError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")

        max_connections = _integer(raw, "MAX_CONNECTIONS", 2048, 1, 65535)
        max_connections_per_ip = _integer(raw, "MAX_CONNECTIONS_PER_IP", 64, 1, max_connections)
        route_cooldown_seconds = _number(
            raw,
            "ROUTE_COOLDOWN_SECONDS",
            30.0,
            1.0,
            3600.0,
        )
        route_max_cooldown_seconds = _number(
            raw,
            "ROUTE_MAX_COOLDOWN_SECONDS",
            max(300.0, route_cooldown_seconds),
            route_cooldown_seconds,
            86400.0,
        )

        return cls(
            listen_host=listen_host,
            listen_port=_integer(raw, "LISTEN_PORT", None, 1, 65535),
            allowed_client_cidrs=_ipv4_networks(raw),
            routes=routes,
            bypass_method=bypass_method,
            connect_timeout_seconds=_number(raw, "CONNECT_TIMEOUT_SECONDS", 5.0, 0.1, 60.0),
            injection_timeout_seconds=_number(raw, "INJECTION_TIMEOUT_SECONDS", 2.0, 0.1, 30.0),
            idle_timeout_seconds=_number(raw, "IDLE_TIMEOUT_SECONDS", 180.0, 5.0, 86400.0),
            shutdown_grace_seconds=_number(
                raw,
                "SHUTDOWN_GRACE_SECONDS",
                30.0,
                0.0,
                300.0,
            ),
            max_route_attempts=_integer(raw, "MAX_ROUTE_ATTEMPTS", 3, 1, 64),
            route_failure_threshold=_integer(raw, "ROUTE_FAILURE_THRESHOLD", 2, 1, 100),
            route_cooldown_seconds=route_cooldown_seconds,
            route_max_cooldown_seconds=route_max_cooldown_seconds,
            route_latency_alpha=_number(raw, "ROUTE_LATENCY_ALPHA", 0.2, 0.01, 1.0),
            route_exploration_interval=_integer(
                raw,
                "ROUTE_EXPLORATION_INTERVAL",
                16,
                2,
                10000,
            ),
            metrics_interval_seconds=_number(
                raw,
                "METRICS_INTERVAL_SECONDS",
                60.0,
                0.0,
                3600.0,
            ),
            relay_buffer_size=_integer(raw, "RELAY_BUFFER_SIZE", 65536, 4096, 1024 * 1024),
            max_connections=max_connections,
            max_connections_per_ip=max_connections_per_ip,
            listen_backlog=_integer(raw, "LISTEN_BACKLOG", 512, 16, 65535),
            log_level=log_level.upper(),
        )


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    try:
        with config_path.open("r", encoding="utf-8") as file:
            raw = json.load(file)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Invalid JSON in {config_path} at line {exc.lineno}, column {exc.colno}"
        ) from exc

    if not isinstance(raw, dict):
        raise ConfigError("config.json root must be a JSON object")
    return AppConfig.from_mapping(raw)


def _ipv4_networks(raw: dict[str, Any]) -> tuple[IPv4Network, ...]:
    values = raw.get("ALLOWED_CLIENT_CIDRS", ["0.0.0.0/0"])
    if not isinstance(values, list) or not values:
        raise ConfigError("ALLOWED_CLIENT_CIDRS must be a non-empty JSON array")
    if len(values) > 256:
        raise ConfigError("ALLOWED_CLIENT_CIDRS must not contain more than 256 entries")

    networks: list[IPv4Network] = []
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ConfigError(f"ALLOWED_CLIENT_CIDRS[{index}] must be a CIDR string")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR in ALLOWED_CLIENT_CIDRS[{index}]: {value!r}") from exc
        if network.version != 4:
            raise ConfigError("ALLOWED_CLIENT_CIDRS supports only IPv4 in this release")
        networks.append(network)

    return tuple(ipaddress.collapse_addresses(networks))


def _routes(raw: dict[str, Any]) -> tuple[RouteConfig, ...]:
    values = raw.get("ROUTES")
    if "ROUTES" in raw:
        conflicting_keys = tuple(
            key
            for key in ("UPSTREAMS", "CONNECT_IP", "CONNECT_PORT", "FAKE_SNIS", "FAKE_SNI")
            if key in raw
        )
        if conflicting_keys:
            raise ConfigError(
                "ROUTES cannot be combined with legacy routing keys: " + ", ".join(conflicting_keys)
            )
        if not isinstance(values, list) or not values:
            raise ConfigError("ROUTES must be a non-empty JSON array")
        if len(values) > 256:
            raise ConfigError("ROUTES must not contain more than 256 route profiles")

        routes: list[RouteConfig] = []
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise ConfigError(f"ROUTES[{index}] must be a JSON object")
            try:
                route = RouteConfig(
                    upstream=UpstreamEndpoint(
                        ip=_ipv4(value, "IP"),
                        port=_integer(value, "PORT", 443, 1, 65535),
                    ),
                    fake_sni=_hostname(value.get("FAKE_SNI"), "FAKE_SNI"),
                )
            except ConfigError as exc:
                raise ConfigError(f"Invalid ROUTES[{index}]: {exc}") from exc
            routes.append(route)

        result = tuple(routes)
        if len(set(result)) != len(result):
            raise ConfigError("ROUTES must not contain duplicate route profiles")
        return result

    upstreams = _upstreams(raw)
    fake_snis = _fake_snis(raw)
    if len(upstreams) * len(fake_snis) > 256:
        raise ConfigError("UPSTREAMS x FAKE_SNIS must not exceed 256 route profiles")
    return tuple(
        RouteConfig(upstream, fake_sni) for upstream in upstreams for fake_sni in fake_snis
    )


def _fake_snis(raw: dict[str, Any]) -> tuple[str, ...]:
    legacy_sni = raw.get("FAKE_SNI")
    values = raw.get("FAKE_SNIS", [legacy_sni] if legacy_sni else None)
    if not isinstance(values, list) or not values:
        raise ConfigError("FAKE_SNIS must be a non-empty JSON array")

    result = tuple(_hostname(value, "FAKE_SNIS") for value in values)
    if len(set(result)) != len(result):
        raise ConfigError("FAKE_SNIS must not contain duplicates")
    return result


def _upstreams(raw: dict[str, Any]) -> tuple[UpstreamEndpoint, ...]:
    values = raw.get("UPSTREAMS")
    if values is None:
        return (
            UpstreamEndpoint(
                ip=_ipv4(raw, "CONNECT_IP"),
                port=_integer(raw, "CONNECT_PORT", None, 1, 65535),
            ),
        )

    if not isinstance(values, list) or not values:
        raise ConfigError("UPSTREAMS must be a non-empty JSON array")
    if len(values) > 64:
        raise ConfigError("UPSTREAMS must not contain more than 64 endpoints")

    endpoints: list[UpstreamEndpoint] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ConfigError(f"UPSTREAMS[{index}] must be a JSON object")
        endpoints.append(
            UpstreamEndpoint(
                ip=_ipv4(value, "IP"),
                port=_integer(value, "PORT", 443, 1, 65535),
            )
        )

    result = tuple(endpoints)
    if len(set(result)) != len(result):
        raise ConfigError("UPSTREAMS must not contain duplicate IP/port pairs")
    return result


def _ipv4(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be an IPv4 address string")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{key} is not a valid IP address: {value!r}") from exc
    if parsed.version != 4:
        raise ConfigError(f"{key} must be IPv4 in this release")
    return str(parsed)


def _hostname(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} entries must be non-empty hostnames")

    hostname = value.strip().rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigError(f"Invalid hostname in {key}: {value!r}") from exc

    encoded = hostname.encode("ascii")
    if len(encoded) > 219:
        raise ConfigError(f"Hostname in {key} exceeds the 219-byte template limit")

    labels = hostname.split(".")
    if len(labels) < 2:
        raise ConfigError(f"Hostname in {key} must contain at least one dot: {value!r}")
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise ConfigError(f"Invalid DNS label length in {key}: {value!r}")
        if label[0] == "-" or label[-1] == "-":
            raise ConfigError(f"DNS labels cannot start or end with '-' in {key}")
        if not all(char.isalnum() or char == "-" for char in label):
            raise ConfigError(f"Unsupported character in hostname for {key}: {value!r}")
    return hostname


def _integer(
    raw: dict[str, Any],
    key: str,
    default: int | None,
    minimum: int,
    maximum: int,
) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{key} must be between {minimum} and {maximum}")
    return value


def _number(raw: dict[str, Any], key: str, default: float, minimum: float, maximum: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ConfigError(f"{key} must be between {minimum} and {maximum}")
    return result
