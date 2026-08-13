from __future__ import annotations

import ipaddress
import unittest

from client_allowlist import ClientAllowlist


class ClientAllowlistTests(unittest.TestCase):
    def test_accepts_only_addresses_inside_configured_networks(self) -> None:
        allowlist = ClientAllowlist(
            (
                ipaddress.ip_network("192.0.2.10/32"),
                ipaddress.ip_network("198.51.100.0/28"),
            )
        )

        self.assertTrue(allowlist.allows("192.0.2.10"))
        self.assertTrue(allowlist.allows("198.51.100.14"))
        self.assertFalse(allowlist.allows("198.51.100.16"))
        self.assertFalse(allowlist.allows("not-an-ip"))

    def test_detects_explicit_allow_all(self) -> None:
        allowlist = ClientAllowlist((ipaddress.ip_network("0.0.0.0/0"),))

        self.assertTrue(allowlist.allows_all)
        self.assertTrue(allowlist.allows("203.0.113.7"))


if __name__ == "__main__":
    unittest.main()
