import unittest

from fed_fernet import FedFernet, FederationGroup
from utils_crypto import generate_aes_key, generate_rsa_key_pair


class FedFernetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.member_private, self.member_public = generate_rsa_key_pair()
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
        self.assertTrue(
            FedFernet.verify_group_signature(
                opened["plaintext"],
                opened["group_signature"],
                [self.member_public],
            )
        )
        self.assertEqual(
            FedFernet.open_trace(
                opened["trace_vault"], self.arbiter_private, opened["plaintext"]
            ),
            "member-a",
        )

    def test_group_signature_does_not_match_unknown_member(self) -> None:
        _, unknown_member_public = generate_rsa_key_pair()
        opened = FedFernet.open(self._seal(), self.federation_key)

        self.assertFalse(
            FedFernet.verify_group_signature(
                opened["plaintext"],
                opened["group_signature"],
                [unknown_member_public],
            )
        )

    def test_federation_group_accepts_registered_members_only(self) -> None:
        second_member_private, second_member_public = generate_rsa_key_pair()
        group = FederationGroup()
        group.add_member("member-a", self.member_public)
        group.add_member("member-b", second_member_public)

        opened = FedFernet.open(self._seal(), self.federation_key)
        self.assertTrue(group.verify(opened["plaintext"], opened["group_signature"]))
        self.assertEqual(group.member_ids, ("member-a", "member-b"))

        group.remove_member("member-a")
        self.assertFalse(group.verify(opened["plaintext"], opened["group_signature"]))

        second_token = FedFernet.seal(
            self.plaintext,
            self.federation_key,
            second_member_private,
            "member-b",
            self.arbiter_public,
            "r-1",
            b"tsa-token",
        )
        second_opened = FedFernet.open(second_token, self.federation_key)
        self.assertTrue(
            group.verify(
                second_opened["plaintext"], second_opened["group_signature"]
            )
        )

    def test_federation_group_rejects_duplicate_or_unknown_members(self) -> None:
        group = FederationGroup()
        group.add_member("member-a", self.member_public)

        with self.assertRaises(ValueError):
            group.add_member("member-a", self.member_public)
        with self.assertRaises(ValueError):
            group.remove_member("unknown")

    def test_tampering_is_rejected(self) -> None:
        token = bytearray(self._seal())
        body_start = token.index(ord("."), 4) + 1
        token[body_start] = ord("A") if token[body_start] != ord("A") else ord("B")

        with self.assertRaises(Exception):
            FedFernet.open(bytes(token), self.federation_key)

    def test_wrong_federation_key_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            FedFernet.open(self._seal(), generate_aes_key())

    def test_wrong_arbiter_key_is_rejected(self) -> None:
        _, wrong_arbiter_private = generate_rsa_key_pair()

        opened = FedFernet.open(self._seal(), self.federation_key)
        with self.assertRaises(Exception):
            FedFernet.open_trace(
                opened["trace_vault"], wrong_arbiter_private, opened["plaintext"]
            )

    def test_changed_plaintext_fails_signature_validation(self) -> None:
        opened = FedFernet.open(self._seal(), self.federation_key)

        with self.assertRaises(Exception):
            FedFernet.open_trace(
                opened["trace_vault"], self.arbiter_private, b"changed"
            )

    def test_invalid_inputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FedFernet.seal(
                self.plaintext,
                b"short-key",
                self.member_private,
                "member-a",
                self.arbiter_public,
                "r-1",
                b"tsa-token",
            )

        with self.assertRaises(ValueError):
            FedFernet.seal(
                self.plaintext,
                self.federation_key,
                self.member_private,
                "",
                self.arbiter_public,
                "r-1",
                b"tsa-token",
            )


if __name__ == "__main__":
    unittest.main()