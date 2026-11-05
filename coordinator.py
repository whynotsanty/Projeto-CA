"""Persistent Federation Coordinator state and key epochs."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from utils_crypto import generate_aes_key, load_public_key


class FederationCoordinator:
    """Manage members, revocation and federation encryption key epochs."""

    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self._members: dict[str, str] = {}
        self._revoked: set[str] = set()
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
        load_public_key(public_key_pem)
        self._members[member_id] = self._encode(public_key_pem)
        self._revoked.discard(member_id)

    def revoke_member(self, member_id: str) -> None:
        if member_id not in self._members:
            raise ValueError("member is not registered")
        self._revoked.add(member_id)
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
        """Return current and historical member keys for old reports."""
        return [self._decode(value) for value in self._members.values()]

    def active_member_ids(self) -> tuple[str, ...]:
        return tuple(member_id for member_id in self._members if self.is_active(member_id))

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
        return self._current_epoch

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "version": 1,
            "current_epoch": self._current_epoch,
            "members": self._members,
            "revoked_members": sorted(self._revoked),
            "epochs": self._epochs,
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
        self._epochs = dict(state["epochs"])
        self.current_key()
