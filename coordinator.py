"""Estado persistente do Coordinator e epochs de chaves."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils_crypto import generate_aes_key, load_public_key


class FederationCoordinator:
    """Gere membros, revogacao e epochs das chaves da federacao."""

    def __init__(self, state_path: str | Path, state_encryption_key: bytes) -> None:
        self.state_path = Path(state_path)
        if len(state_encryption_key) != 32:
            raise ValueError("a chave do estado deve ter 32 bytes")
        self._state_encryption_key = state_encryption_key
        self._members: dict[str, str] = {}
        self._revoked: set[str] = set()
        self._revocations: dict[str, dict[str, Any]] = {}
        self._epochs: dict[str, str] = {}
        self._current_epoch = 0
        if self.state_path.exists():
            self._load()
        elif not self._epochs:
            self._epochs["0"] = self._encode(generate_aes_key())

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value.encode("ascii"))

    def register_member(self, member_id: str, public_key_pem: bytes) -> None:
        if not member_id:
            raise ValueError("member_id is required")
        if member_id in self._members and member_id not in self._revoked:
            raise ValueError("member is already registered")
        if member_id in self._revoked and self.member_public_key(member_id) == public_key_pem:
            raise ValueError("a chave de um membro revogado nao pode ser reutilizada")
        load_public_key(public_key_pem)
        self._members[member_id] = self._encode(public_key_pem)
        self._revoked.discard(member_id)
        self._revocations.pop(member_id, None)
        self.save()

    def revoke_member(self, member_id: str, reason: str = "") -> None:
        if member_id not in self._members:
            raise ValueError("member is not registered")
        if member_id in self._revoked:
            raise ValueError("member ja esta revogado")
        self._revoked.add(member_id)
        self._revocations[member_id] = {
            "member_id": member_id,
            "revoked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "effective_epoch": self._current_epoch + 1,
            "reason": reason,
        }
        self.rotate_key()

    def is_active(self, member_id: str) -> bool:
        return member_id in self._members and member_id not in self._revoked

    def active_public_keys(self) -> list[bytes]:
        return [
            self._decode(value)
            for member_id, value in self._members.items()
            if self.is_active(member_id)
        ]

    def all_public_keys(self) -> list[bytes]:
        """Devolve chaves atuais e historicas para validar relatorios antigos."""
        return [self._decode(value) for value in self._members.values()]

    def active_member_ids(self) -> tuple[str, ...]:
        return tuple(member_id for member_id in self._members if self.is_active(member_id))

    def revocation_list(self) -> dict[str, object]:
        """Devolve a CRL atual para distribuicao aos membros ativos."""
        return {
            "version": 1,
            "current_epoch": self._current_epoch,
            "revoked_members": [
                self._revocations[member_id]
                for member_id in sorted(self._revocations)
            ],
        }

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    def current_key(self) -> bytes:
        return self._decode(self._epochs[str(self._current_epoch)])

    def key_for_epoch(self, epoch: int) -> bytes:
        try:
            return self._decode(self._epochs[str(epoch)])
        except KeyError as exc:
            raise ValueError("unknown federation key epoch") from exc

    def member_public_key(self, member_id: str) -> bytes:
        try:
            return self._decode(self._members[member_id])
        except KeyError as exc:
            raise ValueError("member is not registered") from exc

    def rotate_key(self) -> int:
        self._current_epoch += 1
        self._epochs[str(self._current_epoch)] = self._encode(generate_aes_key())
        self.save()
        return self._current_epoch

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        epochs_data = json.dumps(self._epochs, sort_keys=True).encode("utf-8")
        nonce = secrets.token_bytes(12)
        encrypted_epochs = AESGCM(self._state_encryption_key).encrypt(
            nonce, epochs_data, b"FedFernet:coordinator-state:v1"
        )
        state = {
            "version": 1,
            "current_epoch": self._current_epoch,
            "members": self._members,
            "revoked_members": sorted(self._revoked),
            "revocations": self._revocations,
            "epochs_nonce": self._encode(nonce),
            "epochs_ciphertext": self._encode(encrypted_epochs),
        }
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True, indent=2), encoding="utf-8")
        temporary.replace(self.state_path)

    def _load(self) -> None:
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if state.get("version") != 1:
            raise ValueError("unsupported coordinator state version")
        self._current_epoch = int(state["current_epoch"])
        self._members = dict(state["members"])
        self._revoked = set(state["revoked_members"])
        self._revocations = dict(state.get("revocations", {}))
        nonce = self._decode(state["epochs_nonce"])
        encrypted_epochs = self._decode(state["epochs_ciphertext"])
        epochs_data = AESGCM(self._state_encryption_key).decrypt(
            nonce, encrypted_epochs, b"FedFernet:coordinator-state:v1"
        )
        self._epochs = dict(json.loads(epochs_data))
        self.current_key()
