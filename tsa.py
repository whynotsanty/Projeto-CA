"""Tokens de timestamp confiavel verificaveis para o prototipo."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

from utils_crypto import generate_rsa_key_pair, load_private_key, load_public_key, sign, verify


class TrustedTimestampAuthority:
    """Emite tokens assinados e verifica a carga associada."""

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
        unsigned = {
            "version": 1,
            "serial": str(uuid4()),
            "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "sha256": digest,
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
            issued_at = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if value.get("version") != 1:
                return False
            if value.get("sha256") != hashlib.sha256(payload).hexdigest():
                return False
            if issued_at > datetime.now(timezone.utc) + timedelta(
                seconds=maximum_future_seconds
            ):
                return False
            verify(load_public_key(tsa_public_key_pem), signature, encoded)
        except Exception:
            return False
        return True
