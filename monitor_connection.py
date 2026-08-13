from __future__ import annotations

import socket
import threading


class MonitorConnection:
    def __init__(
        self,
        sock: socket.socket,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.thread_lock = threading.RLock()
        self.sock = sock

    def deactivate(self) -> None:
        with self.thread_lock:
            self.monitor = False
