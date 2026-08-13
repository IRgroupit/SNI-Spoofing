from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app_config import AppConfig, ConfigError, load_config


def valid_config() -> dict[str, object]:
    return {
        "LISTEN_HOST": "0.0.0.0",
        "LISTEN_PORT": 40443,
        "CONNECT_IP": "188.114.98.0",
        "CONNECT_PORT": 443,
        "FAKE_SNIS": ["aparat.com"],
    }


class AppConfigTests(unittest.TestCase):
    def test_accepts_public_listener_and_aparat_decoy(self) -> None:
        config = AppConfig.from_mapping(valid_config())

        self.assertEqual(config.listen_host, "0.0.0.0")
        self.assertEqual(config.fake_snis, ("aparat.com",))
        self.assertEqual(config.relay_buffer_size, 65536)
        self.assertEqual(config.max_route_attempts, 3)
        self.assertEqual(str(config.allowed_client_cidrs[0]), "0.0.0.0/0")

    def test_supports_multiple_upstreams_and_compatibility_aliases(self) -> None:
        raw = valid_config()
        raw.pop("CONNECT_IP")
        raw.pop("CONNECT_PORT")
        raw["UPSTREAMS"] = [
            {"IP": "192.0.2.10", "PORT": 443},
            {"IP": "192.0.2.20", "PORT": 8443},
        ]

        config = AppConfig.from_mapping(raw)

        self.assertEqual(
            tuple(endpoint.label for endpoint in config.upstreams),
            ("192.0.2.10:443", "192.0.2.20:8443"),
        )
        self.assertEqual(config.connect_ip, "192.0.2.10")
        self.assertEqual(config.connect_port, 443)

    def test_rejects_duplicate_upstreams(self) -> None:
        raw = valid_config()
        raw["UPSTREAMS"] = [
            {"IP": "192.0.2.10", "PORT": 443},
            {"IP": "192.0.2.10", "PORT": 443},
        ]

        with self.assertRaisesRegex(ConfigError, "duplicate"):
            AppConfig.from_mapping(raw)

    def test_parses_and_collapses_client_cidrs(self) -> None:
        raw = valid_config()
        raw["ALLOWED_CLIENT_CIDRS"] = [
            "192.0.2.1/24",
            "192.0.2.128/25",
            "198.51.100.10",
        ]

        config = AppConfig.from_mapping(raw)

        self.assertEqual(
            tuple(str(network) for network in config.allowed_client_cidrs),
            ("192.0.2.0/24", "198.51.100.10/32"),
        )

    def test_rejects_ipv6_client_cidr(self) -> None:
        raw = valid_config()
        raw["ALLOWED_CLIENT_CIDRS"] = ["2001:db8::/32"]

        with self.assertRaisesRegex(ConfigError, "only IPv4"):
            AppConfig.from_mapping(raw)

    def test_rejects_max_cooldown_below_base_cooldown(self) -> None:
        raw = valid_config()
        raw["ROUTE_COOLDOWN_SECONDS"] = 60
        raw["ROUTE_MAX_COOLDOWN_SECONDS"] = 30

        with self.assertRaisesRegex(ConfigError, "between 60"):
            AppConfig.from_mapping(raw)

    def test_supports_legacy_fake_sni_key(self) -> None:
        raw = valid_config()
        raw.pop("FAKE_SNIS")
        raw["FAKE_SNI"] = "auth.vercel.com"

        config = AppConfig.from_mapping(raw)

        self.assertEqual(config.fake_snis, ("auth.vercel.com",))

    def test_rejects_invalid_hostname(self) -> None:
        raw = valid_config()
        raw["FAKE_SNIS"] = ["not a hostname"]

        with self.assertRaises(ConfigError):
            AppConfig.from_mapping(raw)

    def test_rejects_per_ip_limit_above_global_limit(self) -> None:
        raw = valid_config()
        raw["MAX_CONNECTIONS"] = 10
        raw["MAX_CONNECTIONS_PER_IP"] = 11

        with self.assertRaises(ConfigError):
            AppConfig.from_mapping(raw)

    def test_load_config_reports_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{invalid", encoding="utf-8")

            with self.assertRaisesRegex(ConfigError, "Invalid JSON"):
                load_config(path)

    def test_load_config_from_disk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(valid_config()), encoding="utf-8")

            self.assertEqual(load_config(path).connect_port, 443)


if __name__ == "__main__":
    unittest.main()
