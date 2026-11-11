"""Adaptador Kafka para o contrato pull-based da federacao."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from kafka.admin import (
    ACLFilter,
    ACLOperation,
    ACLPermissionType,
    ACLResourcePatternType,
    KafkaAdminClient,
    ResourcePattern,
    ResourceType,
)
from kafka import KafkaConsumer, KafkaProducer

from tor_transport import TorSocks5Transport

TOPIC_EVENTS = "fed.v1.events"
TOPIC_REVOCATIONS = "fed.v1.coordinator.revocations"
TOPIC_EPOCHS = "fed.v1.coordinator.epochs"
SUPPORTED_KINDS = {"report", "corroboration", "dispute"}
FEDERATION_TOPICS = (TOPIC_EVENTS, TOPIC_REVOCATIONS, TOPIC_EPOCHS)


class KafkaAccessController:
    """Remove ACLs Kafka de um membro revogado."""

    def __init__(
        self,
        bootstrap_servers: str | list[str],
        *,
        admin_client_factory: Any | None = None,
    ) -> None:
        factory = admin_client_factory or KafkaAdminClient
        self._admin = factory(bootstrap_servers=bootstrap_servers)

    def revoke_member_access(self, member_id: str) -> None:
        self._admin.delete_acls(
            [
                ACLFilter(
                    principal=f"User:{member_id}",
                    host="*",
                    operation=ACLOperation.ANY,
                    permission_type=ACLPermissionType.ANY,
                    resource_pattern=ResourcePattern(
                        ResourceType.TOPIC,
                        topic,
                        ACLResourcePatternType.LITERAL,
                    ),
                )
                for topic in FEDERATION_TOPICS
            ]
        )

    def close(self) -> None:
        self._admin.close()


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


class KafkaBrokerClient:
    """Publica tokens FedFernet num log Kafka e recupera-os por offset."""

    def __init__(
        self,
        bootstrap_servers: str | list[str],
        *,
        group_id: str | None = None,
        client_id: str | None = None,
        tor_transport: TorSocks5Transport | None = None,
        consumer_factory: Any | None = None,
        producer_factory: Any | None = None,
    ) -> None:
        self.client_id = client_id or f"fed-client-{uuid4()}"
        self.group_id = group_id or self.client_id
        self._tor_transport = tor_transport
        if self._tor_transport is not None:
            self._tor_transport.install()
        make_consumer = consumer_factory or KafkaConsumer
        make_producer = producer_factory or KafkaProducer
        try:
            self._consumer = make_consumer(
                TOPIC_EVENTS,
                bootstrap_servers=bootstrap_servers,
                group_id=self.group_id,
                client_id=self.client_id,
                enable_auto_commit=True,
                auto_offset_reset="earliest",
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
            )
            self._producer = make_producer(
                bootstrap_servers=bootstrap_servers,
                client_id=self.client_id,
                value_serializer=lambda value: json.dumps(value, sort_keys=True).encode("utf-8"),
            )
        except Exception:
            if self._tor_transport is not None:
                self._tor_transport.close()
            raise
        self._messages: dict[int, BrokerMessage] = {}

    def close(self) -> None:
        self._producer.flush()
        self._consumer.close()
        if self._tor_transport is not None:
            self._tor_transport.close()

    def publish(
        self,
        payload: bytes,
        *,
        kind: str,
        report_id: str | None,
        epoch: int,
    ) -> BrokerMessage:
        if kind not in SUPPORTED_KINDS:
            raise ValueError("unsupported broker message kind")
        message = BrokerMessage(0, str(uuid4()), kind, report_id, epoch, payload)
        record = self._producer.send(TOPIC_EVENTS, message.to_dict()).get(timeout=10)
        message = BrokerMessage(record.offset, message.message_id, kind, report_id, epoch, payload)
        self._producer.flush()
        self._messages[message.sequence] = message
        return message

    def pull(self, after_sequence: int = 0) -> list[BrokerMessage]:
        records = self._consumer.poll(timeout_ms=1000)
        for partition_records in records.values():
            for record in partition_records:
                value = record.value
                message = BrokerMessage.from_dict(value)
                message = BrokerMessage(
                    record.offset,
                    message.message_id,
                    message.kind,
                    message.report_id,
                    message.epoch,
                    message.payload,
                )
                self._messages[message.sequence] = message
        return [
            message
            for sequence, message in sorted(self._messages.items())
            if sequence > after_sequence
        ]

    def publish_control(self, topic: str, value: dict[str, object]) -> None:
        if topic not in {TOPIC_REVOCATIONS, TOPIC_EPOCHS}:
            raise ValueError("topico de controlo invalido")
        self._producer.send(topic, value).get(timeout=10)
        self._producer.flush()