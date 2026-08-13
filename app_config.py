from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when config.json contains an unsafe or unsupported value."""


@dataclass(frozen=True, slots=True)
class AppConfig:
    listen_host: str
    listen_port: int
    connect_ip: str
    connect_port: int
    fake_snis: tuple[str, ...]
    bypass_method: str
    connect_timeout_seconds: float
    injection_timeout_seconds: float
    idle_timeout_seconds: float
    relay_buffer_size: int
    max_connections: int
    max_connections_per_ip: int
    listen_backlog: int
    log_level: str

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> AppConfig:
        listen_host = _ipv4(raw, "LISTEN_HOST")
        connect_ip = _ipv4(raw, "CONNECT_IP")

        legacy_sni = raw.get("FAKE_SNI")
        sni_values = raw.get("FAKE_SNIS", [legacy_sni] if legacy_sni else None)
        if not isinstance(sni_values, list) or not sni_values:
            raise ConfigError("FAKE_SNIS must be a non-empty JSON array")

        fake_snis = tuple(_hostname(value, "FAKE_SNIS") for value in sni_values)
        if len(set(fake_snis)) != len(fake_snis):
            raise ConfigError("FAKE_SNIS must not contain duplicates")

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

        return cls(
            listen_host=listen_host,
            listen_port=_integer(raw, "LISTEN_PORT", None, 1, 65535),
            connect_ip=connect_ip,
            connect_port=_integer(raw, "CONNECT_PORT", None, 1, 65535),
            fake_snis=fake_snis,
            bypass_method=bypass_method,
            connect_timeout_seconds=_number(raw, "CONNECT_TIMEOUT_SECONDS", 5.0, 0.1, 60.0),
            injection_timeout_seconds=_number(raw, "INJECTION_TIMEOUT_SECONDS", 2.0, 0.1, 30.0),
            idle_timeout_seconds=_number(raw, "IDLE_TIMEOUT_SECONDS", 180.0, 5.0, 86400.0),
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
