"""Prototype encrypted envelope for the FedFernet project.

This is not a real group-signature implementation. It uses an RSA signature
and an Arbiter-only tracing vault as a logical simulator until a group
signature library or construction is selected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils_crypto import load_private_key, load_public_key, sign, verify


class FedFernet:
    """Create and open authenticated, encrypted federation envelopes."""

    VERSION = 1
    NONCE_SIZE = 12

    @staticmethod
    def seal(
        plaintext: bytes,
        federation_key: bytes,
        signer_private_key_pem: bytes,
        member_id: str,
        arbiter_public_key_pem: bytes,
        report_id: str,
        timestamp_token: bytes,
        *,
        epoch: int = 0,
    ) -> bytes:
        """Create an AES-256-GCM envelope.

        The member signs ``plaintext`` with RSA-PSS. The member identity,
        public key and signature are placed in an Arbiter-only hybrid vault:
        AES-GCM protects the vault contents and RSA-OAEP protects its fresh
        AES key. The deterministic HMAC tag is reserved for corroboration
        de-duplication. The TSA token is opaque and authenticated as part of
        the envelope. ``epoch`` identifies the federation key generation.
        """
        _require_aes_key(federation_key)
        if not member_id or not report_id:
            raise ValueError("member_id and report_id are required")

        signer_private_key = load_private_key(signer_private_key_pem)
        arbiter_public_key = load_public_key(arbiter_public_key_pem)
        signer_public_key_pem = signer_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        signature = sign(signer_private_key, plaintext)

        trace_data = _canonical_json(
            {
                "member_id": member_id,
                "report_id": report_id,
                "signature": _b64(signature),
                "signer_public_key": _b64(signer_public_key_pem),
            }
        )
        trace_key = secrets.token_bytes(32)
        trace_nonce = secrets.token_bytes(FedFernet.NONCE_SIZE)
        trace_ciphertext = AESGCM(trace_key).encrypt(
            trace_nonce, trace_data, b"FedFernet:trace:v1"
        )
        wrapped_trace_key = arbiter_public_key.encrypt(
            trace_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        tag_key = hashlib.sha256(signer_private_key_pem).digest()
        linkability_tag = hmac.new(
            tag_key,
            b"corroboration:" + report_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        envelope = {
            "version": FedFernet.VERSION,
            "epoch": epoch,
            "report_id": report_id,
            "trace_vault": {
                "key": _b64(wrapped_trace_key),
                "nonce": _b64(trace_nonce),
                "ciphertext": _b64(trace_ciphertext),
            },
            "linkability_tag": _b64(linkability_tag),
            "timestamp_token": _b64(timestamp_token),
            "plaintext": _b64(plaintext),
        }
        envelope_bytes = _canonical_json(envelope)
        nonce = secrets.token_bytes(FedFernet.NONCE_SIZE)
        aad = _aad(epoch)
        ciphertext = AESGCM(federation_key).encrypt(nonce, envelope_bytes, aad)
        return b"FF1." + str(epoch).encode("ascii") + b"." + _b64_bytes(nonce + ciphertext)

    @staticmethod
    def open(
        token: bytes,
        federation_key: bytes,
    ) -> dict[str, Any]:
        """Decrypt an envelope and validate its AES-GCM authentication tag.

        The normal open path does not decrypt the Arbiter vault or reveal the
        member identity. Signature verification is performed by ``open_trace``
        in this first logical-simulator version. A future group-signature
        verifier will allow all members to verify membership anonymously.
        """
        _require_aes_key(federation_key)
        parts = token.split(b".", 2)
        if len(parts) != 3 or parts[0] != b"FF1":
            raise ValueError("Unsupported FedFernet token")
        try:
            epoch = int(parts[1])
        except ValueError as exc:
            raise ValueError("Invalid FedFernet epoch") from exc

        raw = _unb64_bytes(parts[2])
        if len(raw) <= FedFernet.NONCE_SIZE:
            raise ValueError("Invalid FedFernet token")
        nonce = raw[: FedFernet.NONCE_SIZE]
        ciphertext = raw[FedFernet.NONCE_SIZE :]
        envelope = json.loads(
            AESGCM(federation_key).decrypt(nonce, ciphertext, _aad(epoch))
        )
        if envelope.get("version") != FedFernet.VERSION or envelope.get("epoch") != epoch:
            raise ValueError("FedFernet metadata mismatch")

        plaintext = _unb64(envelope["plaintext"])
        trace = envelope["trace_vault"]
        # The signature is intentionally hidden in the Arbiter vault in this
        # logical simulator; open_trace performs its verification.
        return {
            "report_id": envelope["report_id"],
            "epoch": epoch,
            "plaintext": plaintext,
            "linkability_tag": _unb64(envelope["linkability_tag"]),
            "timestamp_token": _unb64(envelope["timestamp_token"]),
            "trace_vault": {
                "key": _unb64(trace["key"]),
                "nonce": _unb64(trace["nonce"]),
                "ciphertext": _unb64(trace["ciphertext"]),
            },
        }

    @staticmethod
    def open_trace(
        trace_vault: dict[str, bytes],
        arbiter_private_key_pem: bytes,
        plaintext: bytes,
    ) -> str:
        """Open the Arbiter-only vault and verify the disputed report."""
        arbiter_private_key = load_private_key(arbiter_private_key_pem)
        trace_key = arbiter_private_key.decrypt(
            trace_vault["key"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        trace_data = AESGCM(trace_key).decrypt(
            trace_vault["nonce"],
            trace_vault["ciphertext"],
            b"FedFernet:trace:v1",
        )
        trace = json.loads(trace_data)
        verify(
            load_public_key(_unb64(trace["signer_public_key"])),
            _unb64(trace["signature"]),
            plaintext,
        )
        return trace["member_id"]


def _require_aes_key(key: bytes) -> None:
    if len(key) != 32:
        raise ValueError("AES-256 keys must be 32 bytes")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(epoch: int) -> bytes:
    return f"FedFernet:v{FedFernet.VERSION}:epoch:{epoch}".encode("ascii")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _b64_bytes(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value)


def _unb64_bytes(value: bytes) -> bytes:
    return base64.urlsafe_b64decode(value)