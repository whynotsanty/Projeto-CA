"""A pull-based broker that stores opaque encrypted publications."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class BrokerMessage:
    sequence: int
    message_id: str
    kind: str
    report_id: str | None
    epoch: int
    payload: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "message_id": self.message_id,
            "kind": self.kind,
            "report_id": self.report_id,
            "epoch": self.epoch,
            "payload": base64.urlsafe_b64encode(self.payload).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "BrokerMessage":
        return cls(
            sequence=int(value["sequence"]),
            message_id=str(value["message_id"]),
            kind=str(value["kind"]),
            report_id=value["report_id"] if value["report_id"] is None else str(value["report_id"]),
            epoch=int(value["epoch"]),
            payload=base64.urlsafe_b64decode(str(value["payload"]).encode("ascii")),
        )


class LocalBroker:
    """Filesystem broker used for deterministic offline and integration tests."""

    def __init__(self, storage_path: str | Path) -> None:
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _next_sequence(self) -> int:
        sequences = [
            int(path.stem)
            for path in self.storage_path.glob("*.json")
            if path.stem.isdigit()
        ]
        return max(sequences, default=0) + 1

    def publish(
        self,
        payload: bytes,
        *,
        kind: str,
        report_id: str | None,
        epoch: int,
    ) -> BrokerMessage:
        if kind not in {"report", "corroboration", "dispute"}:
            raise ValueError("unsupported broker message kind")
        sequence = self._next_sequence()
        message = BrokerMessage(sequence, str(uuid4()), kind, report_id, epoch, payload)
        target = self.storage_path / f"{sequence:020d}.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(message.to_dict(), sort_keys=True), encoding="utf-8")
        temporary.replace(target)
        return message

    def pull(self, after_sequence: int = 0) -> list[BrokerMessage]:
        messages: list[BrokerMessage] = []
        for path in sorted(self.storage_path.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            message = BrokerMessage.from_dict(value)
            if message.sequence > after_sequence:
                messages.append(message)
        return messages
