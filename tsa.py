"""Tokens de timestamp confiavel verificaveis para o prototipo."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization

from utils_crypto import generate_rsa_key_pair, load_private_key, load_public_key, sign, verify


class TrustedTimestampAuthority:
    """TSA local baseada nos campos essenciais do RFC 3161."""

    POLICY_OID = "1.3.6.1.4.1.55555.1.1"

    def __init__(self, private_key_pem: bytes | None = None) -> None:
        if private_key_pem is None:
            private_key_pem, public_key_pem = generate_rsa_key_pair()
            self.private_key_pem = private_key_pem
            self.public_key_pem = public_key_pem
        else:
            self.private_key_pem = private_key_pem
            key = load_private_key(private_key_pem)
            self.public_key_pem = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def issue(self, payload: bytes) -> bytes:
        digest = hashlib.sha256(payload).hexdigest()
        issued_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        unsigned = {
            "type": "TimeStampResp",
            "status": {"status": "granted"},
            "version": 1,
            "serial_number": str(secrets.randbits(128)),
            "policy_oid": self.POLICY_OID,
            "message_imprint": {
                "hash_algorithm": "sha256",
                "hashed_message": digest,
            },
            "nonce": str(secrets.randbits(128)),
            "gen_time": issued_at,
            "cert_req": True,
        }
        encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = dict(unsigned)
        token["signature"] = base64.urlsafe_b64encode(
            sign(load_private_key(self.private_key_pem), encoded)
        ).decode("ascii")
        return json.dumps(token, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def verify(
        token: bytes,
        payload: bytes,
        tsa_public_key_pem: bytes,
        *,
        maximum_future_seconds: int = 5,
    ) -> bool:
        try:
            value = json.loads(token)
            signature = base64.urlsafe_b64decode(value.pop("signature").encode("ascii"))
            issued_at = datetime.fromisoformat(value["gen_time"].replace("Z", "+00:00"))
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            imprint = value["message_imprint"]
            digest = hashlib.sha256(payload).hexdigest()
            if (
                value.get("type") != "TimeStampResp"
                or value.get("status", {}).get("status") != "granted"
                or value.get("version") != 1
                or value.get("policy_oid") != TrustedTimestampAuthority.POLICY_OID
                or imprint.get("hash_algorithm") != "sha256"
                or imprint.get("hashed_message") != digest
                or not value.get("serial_number")
                or not value.get("nonce")
            ):
                return False
            if issued_at > datetime.now(timezone.utc) + timedelta(
                seconds=maximum_future_seconds
            ):
                return False
            verify(load_public_key(tsa_public_key_pem), signature, encoded)
        except Exception:
            return False
        return True
