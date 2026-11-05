"""Fluxo da aplicacao entre relatorios, Coordinator, TSA e broker."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import serialization

from broker import BrokerMessage
from coordinator import FederationCoordinator
from fed_fernet import FedFernet
from models import IncidentReport
from tsa import TrustedTimestampAuthority
from utils_crypto import load_private_key


@dataclass(frozen=True)
class PulledReport:
    message: BrokerMessage
    report: IncidentReport
    envelope: dict[str, object]


class BrokerInterface(Protocol):
    """Contrato comum para broker local, HTTP e futuro MQTT."""

    def publish(
        self,
        payload: bytes,
        *,
        kind: str,
        report_id: str | None,
        epoch: int,
    ) -> BrokerMessage: ...

    def pull(self, after_sequence: int = 0) -> list[BrokerMessage]: ...


class FederationService:
    """Publica e recupera relatorios autenticados atraves de um broker nao confiavel."""

    def __init__(
        self,
        coordinator: FederationCoordinator,
        broker: BrokerInterface,
        arbiter_public_key_pem: bytes,
        tsa: TrustedTimestampAuthority,
    ) -> None:
        self.coordinator = coordinator
        self.broker = broker
        self.arbiter_public_key_pem = arbiter_public_key_pem
        self.tsa = tsa
        self._timestamp_by_message: dict[str, str] = {}

    def _verify_timestamp(self, message: BrokerMessage, payload: bytes, token: bytes) -> None:
        try:
            timestamp_data = json.loads(token)
            serial = str(timestamp_data["serial"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("timestamp token invalido") from exc
        previous_message = next(
            (
                message_id
                for message_id, previous_serial in self._timestamp_by_message.items()
                if previous_serial == serial
            ),
            None,
        )
        if previous_message is not None and previous_message != message.message_id:
            raise ValueError("timestamp token repetido")
        if not self.tsa.verify(token, payload, self.tsa.public_key_pem):
            raise ValueError("timestamp token invalido")
        self._timestamp_by_message[message.message_id] = serial

    def _require_active_member(self, member_id: str, private_key_pem: bytes) -> None:
        if not self.coordinator.is_active(member_id):
            raise PermissionError("member is not active")
        private_key = load_private_key(private_key_pem)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if public_key != self.coordinator.member_public_key(member_id):
            raise PermissionError("private key does not belong to member")

    def publish_report(
        self, report: IncidentReport, member_id: str, member_private_key_pem: bytes
    ) -> BrokerMessage:
        self._require_active_member(member_id, member_private_key_pem)
        epoch = self.coordinator.current_epoch
        payload = report.to_json()
        timestamp_token = self.tsa.issue(payload)
        token = FedFernet.seal(
            payload,
            self.coordinator.current_key(),
            member_private_key_pem,
            member_id,
            self.arbiter_public_key_pem,
            report.report_id,
            timestamp_token,
            epoch=epoch,
        )
        return self.broker.publish(
            token, kind="report", report_id=report.report_id, epoch=epoch
        )

    def pull_reports(self, after_sequence: int = 0) -> list[PulledReport]:
        pulled: list[PulledReport] = []
        for message in self.broker.pull(after_sequence):
            if message.kind != "report":
                continue
            envelope = FedFernet.open(
                message.payload, self.coordinator.key_for_epoch(message.epoch)
            )
            if envelope["report_id"] != message.report_id:
                raise ValueError("broker report metadata mismatch")
            plaintext = envelope["plaintext"]
            if not isinstance(plaintext, bytes):
                raise ValueError("invalid report payload")
            if not FedFernet.verify_group_signature(
                plaintext,
                envelope["group_signature"],
                self.coordinator.all_public_keys(),
            ):
                raise ValueError("report is not signed by an active member")
            report = IncidentReport.from_json(plaintext)
            self._verify_timestamp(message, plaintext, envelope["timestamp_token"])
            pulled.append(PulledReport(message, report, envelope))
        return pulled

    def pull_corroborations(
        self, report_id: str, after_sequence: int = 0
    ) -> list[dict[str, object]]:
        """Devolve corroboracoes validas e distintas de um relatorio."""
        result: list[dict[str, object]] = []
        tags: set[bytes] = set()
        for message in self.broker.pull(after_sequence):
            if message.kind != "corroboration" or message.report_id != report_id:
                continue
            envelope = FedFernet.open(
                message.payload, self.coordinator.key_for_epoch(message.epoch)
            )
            content = envelope["plaintext"]
            if not isinstance(content, bytes):
                raise ValueError("corroboracao invalida")
            value = json.loads(content)
            if value != {"report_id": report_id, "type": "corroboration"}:
                raise ValueError("corroboracao invalida")
            if not FedFernet.verify_group_signature(
                content,
                envelope["group_signature"],
                self.coordinator.all_public_keys(),
            ):
                raise ValueError("assinatura de corroboracao invalida")
            self._verify_timestamp(message, content, envelope["timestamp_token"])
            tag = envelope["linkability_tag"]
            if not isinstance(tag, bytes) or tag in tags:
                continue
            tags.add(tag)
            result.append({"message": message, "envelope": envelope})
        return result

    def count_corroborations(self, report_id: str) -> int:
        return len(self.pull_corroborations(report_id))

    def trace_dispute(self, message: BrokerMessage, arbiter_private_key_pem: bytes) -> str:
        """Devolve ao Arbiter o membro por tras de uma disputa valida."""
        if message.kind != "dispute":
            raise ValueError("a mensagem nao e uma disputa")
        envelope = FedFernet.open(
            message.payload, self.coordinator.key_for_epoch(message.epoch)
        )
        content = envelope["plaintext"]
        if not isinstance(content, bytes):
            raise ValueError("disputa invalida")
        value = json.loads(content)
        if value.get("type") != "dispute" or value.get("report_id") != message.report_id:
            raise ValueError("disputa invalida")
        return FedFernet.open_trace(
            envelope["trace_vault"], arbiter_private_key_pem, content
        )

    def publish_corroboration(
        self,
        report_id: str,
        report_linkability_tag: bytes,
        member_id: str,
        member_private_key_pem: bytes,
    ) -> BrokerMessage:
        self._require_active_member(member_id, member_private_key_pem)
        own_tag = FedFernet.make_linkability_tag(member_private_key_pem, report_id)
        if hmac.compare_digest(own_tag, report_linkability_tag):
            raise ValueError("members cannot corroborate their own reports")
        for message in self.broker.pull():
            if message.kind != "corroboration" or message.report_id != report_id:
                continue
            envelope = FedFernet.open(
                message.payload, self.coordinator.key_for_epoch(message.epoch)
            )
            if hmac.compare_digest(envelope["linkability_tag"], own_tag):
                raise ValueError("member already corroborated this report")
        content = json.dumps(
            {"type": "corroboration", "report_id": report_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        epoch = self.coordinator.current_epoch
        token = FedFernet.seal(
            content,
            self.coordinator.current_key(),
            member_private_key_pem,
            member_id,
            self.arbiter_public_key_pem,
            report_id,
            self.tsa.issue(content),
            epoch=epoch,
        )
        return self.broker.publish(
            token, kind="corroboration", report_id=report_id, epoch=epoch
        )

    def publish_dispute(
        self,
        report_id: str,
        reason: str,
        member_id: str,
        member_private_key_pem: bytes,
    ) -> BrokerMessage:
        self._require_active_member(member_id, member_private_key_pem)
        if not reason.strip():
            raise ValueError("dispute reason is required")
        content = json.dumps(
            {"type": "dispute", "report_id": report_id, "reason": reason},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        epoch = self.coordinator.current_epoch
        token = FedFernet.seal(
            content,
            self.coordinator.current_key(),
            member_private_key_pem,
            member_id,
            self.arbiter_public_key_pem,
            report_id,
            self.tsa.issue(content),
            epoch=epoch,
        )
        return self.broker.publish(
            token, kind="dispute", report_id=report_id, epoch=epoch
        )
