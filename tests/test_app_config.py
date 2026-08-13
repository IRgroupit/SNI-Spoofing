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
