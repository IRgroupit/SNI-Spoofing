from __future__ import annotations

import socket


def get_default_interface_ipv4(addr: str = "8.8.8.8", port: int = 53) -> str:
    """Return the IPv4 address selected by the OS route table for a destination."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((addr, port))
        except OSError:
            return ""
        return sock.getsockname()[0]


def configure_tcp_socket(
    sock: socket.socket,
    *,
    keep_idle: int = 30,
    keep_interval: int = 10,
    keep_count: int = 3,
) -> None:
    """Apply portable TCP keepalive settings, skipping unavailable OS options."""

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for option_name, value in (
        ("TCP_KEEPIDLE", keep_idle),
        ("TCP_KEEPINTVL", keep_interval),
        ("TCP_KEEPCNT", keep_count),
    ):
        option = getattr(socket, option_name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError:
            # Some Windows builds expose the constant but reject the option.
            continue


def close_socket(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass
