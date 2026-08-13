from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod

from pydivert import Packet, WinDivert

LOGGER = logging.getLogger(__name__)


class TcpInjector(ABC):
    def __init__(self, w_filter: str) -> None:
        self.w: WinDivert = WinDivert(w_filter)
        self.ready = threading.Event()
        self.startup_error: BaseException | None = None

    @abstractmethod
    def inject(self, packet: Packet) -> None:
        raise NotImplementedError

    def run(self) -> None:
        try:
            with self.w:
                self.ready.set()
                while True:
                    packet = self.w.recv(65535)
                    try:
                        self.inject(packet)
                    except Exception:
                        # Fail open: an internal error must not silently blackhole traffic.
                        LOGGER.exception("Unhandled packet injector error; passing packet through")
                        try:
                            self.w.send(packet, False)
                        except Exception:
                            LOGGER.exception("Failed to pass packet through after injector error")
        except BaseException as exc:
            self.startup_error = exc
            self.ready.set()
            LOGGER.exception("WinDivert injector stopped")
