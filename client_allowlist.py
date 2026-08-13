from __future__ import annotations

import ipaddress
from ipaddress import IPv4Network


class ClientAllowlist:
    """Fast admission check for the configured IPv4 client networks."""

    def __init__(self, networks: tuple[IPv4Network, ...]) -> None:
        if not networks:
            raise ValueError("networks must not be empty")
        self._networks = networks

    @property
    def allows_all(self) -> bool:
        return any(network.prefixlen == 0 for network in self._networks)

    def allows(self, address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        if parsed.version != 4:
            return False
        return any(parsed in network for network in self._networks)
