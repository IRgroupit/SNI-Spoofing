from __future__ import annotations

import unittest

from utils.packet_templates import ClientHelloMaker


class ClientHelloMakerTests(unittest.TestCase):
    def test_aparat_client_hello_round_trip(self) -> None:
        random = bytes(range(32))
        session_id = bytes(reversed(range(32)))
        key_share = b"k" * 32

        payload = ClientHelloMaker.get_client_hello_with(
            random,
            session_id,
            b"aparat.com",
            key_share,
        )
        parsed = ClientHelloMaker.parse_client_hello(payload)

        self.assertEqual(len(payload), 517)
        self.assertEqual(parsed, (random, session_id, "aparat.com", key_share))

    def test_rejects_wrong_random_length(self) -> None:
        with self.assertRaisesRegex(ValueError, "rnd"):
            ClientHelloMaker.get_client_hello_with(
                b"short",
                b"s" * 32,
                b"aparat.com",
                b"k" * 32,
            )

    def test_rejects_oversized_sni(self) -> None:
        with self.assertRaisesRegex(ValueError, "target_sni"):
            ClientHelloMaker.get_client_hello_with(
                b"r" * 32,
                b"s" * 32,
                b"a" * 220,
                b"k" * 32,
            )

    def test_rejects_tampered_template(self) -> None:
        payload = bytearray(
            ClientHelloMaker.get_client_hello_with(
                b"r" * 32,
                b"s" * 32,
                b"aparat.com",
                b"k" * 32,
            )
        )
        payload[100] ^= 1

        with self.assertRaisesRegex(ValueError, "template"):
            ClientHelloMaker.parse_client_hello(bytes(payload))


if __name__ == "__main__":
    unittest.main()
