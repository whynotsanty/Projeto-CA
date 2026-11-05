import unittest

from fed_fernet import FedFernet
from utils_crypto import generate_aes_key, generate_rsa_key_pair


class FedFernetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.member_private, _ = generate_rsa_key_pair()
        self.arbiter_private, self.arbiter_public = generate_rsa_key_pair()
        self.federation_key = generate_aes_key()
        self.plaintext = b'{"report_id":"r-1","incident_type":"ddos"}'

    def _seal(self) -> bytes:
        return FedFernet.seal(
            self.plaintext,
            self.federation_key,
            self.member_private,
            "member-a",
            self.arbiter_public,
            "r-1",
            b"tsa-token",
            epoch=2,
        )

    def test_round_trip_and_arbiter_trace(self) -> None:
        opened = FedFernet.open(self._seal(), self.federation_key)

        self.assertEqual(opened["plaintext"], self.plaintext)
        self.assertEqual(
            FedFernet.open_trace(
                opened["trace_vault"], self.arbiter_private, opened["plaintext"]
            ),
            "member-a",
        )

    def test_tampering_is_rejected(self) -> None:
        token = bytearray(self._seal())
        body_start = token.index(ord("."), 4) + 1
        token[body_start] = ord("A") if token[body_start] != ord("A") else ord("B")

        with self.assertRaises(Exception):
            FedFernet.open(bytes(token), self.federation_key)


if __name__ == "__main__":
    unittest.main()