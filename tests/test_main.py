from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

if "pydivert" not in sys.modules:
    pydivert_stub = types.ModuleType("pydivert")
    pydivert_stub.Packet = object
    pydivert_stub.WinDivert = object
    sys.modules["pydivert"] = pydivert_stub

from main import run  # noqa: E402


class MainTests(unittest.TestCase):
    @patch("main.get_default_interface_ipv4", return_value="192.0.2.1")
    def test_check_config_validates_routes_without_starting_driver(
        self,
        interface_resolver: Mock,
    ) -> None:
        raw = {
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "ROUTES": [
                {"IP": "198.51.100.10", "PORT": 443, "FAKE_SNI": "one.example"},
                {"IP": "198.51.100.20", "PORT": 8443, "FAKE_SNI": "two.example"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            output = io.StringIO()

            with (
                patch.dict(sys.modules, {"fake_tcp": None}),
                redirect_stdout(output),
            ):
                result = run(("--config", str(path), "--check-config"))

        self.assertEqual(result, 0)
        self.assertIn("2 route(s), 2 upstream(s)", output.getvalue())
        self.assertEqual(interface_resolver.call_count, 2)


if __name__ == "__main__":
    unittest.main()
