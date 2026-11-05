"""Validated JSON models required by the federation protocol."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


INCIDENT_TYPES = {"ddos", "scanning", "botnet_c2", "prefix_hijacking", "other"}
SEVERITIES = {"low", "medium", "high", "critical"}
MITIGATIONS = {"rate_limiting", "blackholing", "filtering", "monitoring"}


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a UTC timezone")
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class IncidentReport:
    """The exact report content required by the assignment."""

    report_id: str
    incident_type: str
    indicators: dict[str, list[Any]]
    observation_start: datetime
    observation_end: datetime
    severity: str
    recommended_mitigation: str

    def __post_init__(self) -> None:
        try:
            uuid.UUID(self.report_id)
        except ValueError as exc:
            raise ValueError("report_id must be a UUID") from exc
        if self.incident_type not in INCIDENT_TYPES:
            raise ValueError("unsupported incident_type")
        if self.severity not in SEVERITIES:
            raise ValueError("unsupported severity")
        if self.recommended_mitigation not in MITIGATIONS:
            raise ValueError("unsupported recommended_mitigation")
        required = {"source_prefixes", "source_asns", "destination_ports", "protocols"}
        if set(self.indicators) != required:
            raise ValueError("indicators must contain the required fields")
        if self.observation_start >= self.observation_end:
            raise ValueError("observation period must have a positive duration")
        _utc_iso(self.observation_start)
        _utc_iso(self.observation_end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "incident_type": self.incident_type,
            "indicators": self.indicators,
            "observation_period": {
                "start": _utc_iso(self.observation_start),
                "end": _utc_iso(self.observation_end),
            },
            "severity": self.severity,
            "recommended_mitigation": self.recommended_mitigation,
        }

    def to_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IncidentReport":
        expected = {
            "report_id",
            "incident_type",
            "indicators",
            "observation_period",
            "severity",
            "recommended_mitigation",
        }
        if set(value) != expected:
            raise ValueError("report does not match the required JSON structure")
        period = value["observation_period"]
        if not isinstance(period, dict) or set(period) != {"start", "end"}:
            raise ValueError("invalid observation_period")
        return cls(
            report_id=value["report_id"],
            incident_type=value["incident_type"],
            indicators=value["indicators"],
            observation_start=_parse_utc(period["start"]),
            observation_end=_parse_utc(period["end"]),
            severity=value["severity"],
            recommended_mitigation=value["recommended_mitigation"],
        )

    @classmethod
    def from_json(cls, payload: bytes) -> "IncidentReport":
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError("report JSON must be an object")
        return cls.from_dict(value)
