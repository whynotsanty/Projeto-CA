import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from coordinator import FederationCoordinator
from federation_service import FederationService
from kafka_broker import (
    KafkaBrokerClient,
    TOPIC_EPOCHS,
    TOPIC_EVENTS,
    TOPIC_REVOCATIONS,
)
from models import IncidentReport
from tsa import TrustedTimestampAuthority
from utils_crypto import generate_rsa_key_pair
from utils_crypto import generate_aes_key


class FakeKafkaFuture:
    def __init__(self, record: object) -> None:
        self.record = record

    def get(self, timeout: int) -> object:
        return self.record


class FakeKafkaRecord:
    def __init__(self, offset: int, value: dict[str, object]) -> None:
        self.offset = offset
        self.value = value


class FakeKafkaCluster:
    def __init__(self) -> None:
        self.records: list[FakeKafkaRecord] = []

    def producer(self, **_kwargs: object) -> "FakeKafkaProducer":
        return FakeKafkaProducer(self)

    def consumer(self, _topic: str, **_kwargs: object) -> "FakeKafkaConsumer":
        return FakeKafkaConsumer(self)


class FakeKafkaProducer:
    def __init__(self, cluster: FakeKafkaCluster) -> None:
        self.cluster = cluster

    def send(self, topic: str, value: dict[str, object]) -> FakeKafkaFuture:
        offset = len(self.cluster.records)
        record = FakeKafkaRecord(offset, value)
        self.cluster.records.append(record)
        return FakeKafkaFuture(record)

    def flush(self) -> None:
        return


class FakeKafkaConsumer:
    def __init__(self, cluster: FakeKafkaCluster) -> None:
        self.cluster = cluster
        self.position = 0

    def poll(self, timeout_ms: int) -> dict[object, list[FakeKafkaRecord]]:
        records = self.cluster.records[self.position :]
        self.position = len(self.cluster.records)
        return {TOPIC_EVENTS: records} if records else {}

    def close(self) -> None:
        return


class FakeKafkaAdmin:
    def __init__(self, **_kwargs: object) -> None:
        self.deleted_filters: list[object] = []

    def delete_acls(self, filters: list[object]) -> None:
        self.deleted_filters.extend(filters)

    def close(self) -> None:
        return


class FederationProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.member_a_private, self.member_a_public = generate_rsa_key_pair()
        self.member_b_private, self.member_b_public = generate_rsa_key_pair()
        self.arbiter_private, self.arbiter_public = generate_rsa_key_pair()
        self.tsa = TrustedTimestampAuthority()
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.state_key = generate_aes_key()
        self.coordinator = FederationCoordinator(root / "coordinator.json", self.state_key)
        self.coordinator.register_member("member-a", self.member_a_public)
        self.coordinator.register_member("member-b", self.member_b_public)
        self.coordinator.save()
        self.kafka = FakeKafkaCluster()
        self.broker = KafkaBrokerClient(
            "broker.test",
            consumer_factory=self.kafka.consumer,
            producer_factory=self.kafka.producer,
        )
        self.service = FederationService(
            self.coordinator, self.broker, self.arbiter_public, self.tsa
        )
        start = datetime(2026, 11, 20, 14, 5, tzinfo=timezone.utc)
        self.report = IncidentReport(
            report_id=str(uuid4()),
            incident_type="ddos",
            indicators={
                "source_prefixes": ["203.0.113.0/24"],
                "source_asns": [64500],
                "destination_ports": [53],
                "protocols": ["udp"],
            },
            observation_start=start,
            observation_end=start + timedelta(minutes=10),
            severity="high",
            recommended_mitigation="rate_limiting",
        )

    def tearDown(self) -> None:
        self.broker.close()
        self.tempdir.cleanup()

    def test_publish_pull_and_broker_does_not_see_plaintext(self) -> None:
        message = self.service.publish_report(
            self.report, "member-a", self.member_a_private
        )
        pulled = self.service.pull_reports()

        self.assertEqual(message.sequence, 0)
        self.assertEqual(pulled[0].report, self.report)
        self.assertNotIn(self.report.to_json(), json.dumps(self.kafka.records[0].value))

    def test_corroboration_is_once_per_member_and_not_self(self) -> None:
        self.service.publish_report(self.report, "member-a", self.member_a_private)
        opened = self.service.pull_reports()[0].envelope
        report_tag = opened["linkability_tag"]

        self.service.publish_corroboration(
            self.report.report_id,
            report_tag,
            "member-b",
            self.member_b_private,
        )
        with self.assertRaises(ValueError):
            self.service.publish_corroboration(
                self.report.report_id,
                report_tag,
                "member-b",
                self.member_b_private,
            )
        with self.assertRaises(ValueError):
            self.service.publish_corroboration(
                self.report.report_id,
                report_tag,
                "member-a",
                self.member_a_private,
            )
        self.assertEqual(self.service.count_corroborations(self.report.report_id), 1)

    def test_dispute_is_traceable_by_the_arbiter(self) -> None:
        dispute = self.service.publish_dispute(
            self.report.report_id,
            "os indicadores nao correspondem ao periodo observado",
            "member-b",
            self.member_b_private,
        )
        self.assertEqual(
            self.service.trace_dispute(dispute, self.arbiter_private), "member-b"
        )

    def test_replayed_timestamp_token_is_rejected(self) -> None:
        report_message = self.service.publish_report(
            self.report, "member-a", self.member_a_private
        )
        self.broker.publish(
            report_message.payload,
            kind="report",
            report_id=self.report.report_id,
            epoch=report_message.epoch,
        )
        with self.assertRaises(ValueError):
            self.service.pull_reports()

    def test_revocation_rotates_epoch_and_preserves_old_history(self) -> None:
        self.service.publish_report(self.report, "member-a", self.member_a_private)
        old_epoch = self.coordinator.current_epoch
        self.coordinator.revoke_member("member-a")
        self.assertNotEqual(self.coordinator.current_epoch, old_epoch)

        with self.assertRaises(PermissionError):
            self.service.publish_report(self.report, "member-a", self.member_a_private)

        new_report = IncidentReport(
            report_id=str(uuid4()),
            incident_type="scanning",
            indicators=self.report.indicators,
            observation_start=self.report.observation_start,
            observation_end=self.report.observation_end,
            severity="medium",
            recommended_mitigation="monitoring",
        )
        self.service.publish_report(new_report, "member-b", self.member_b_private)
        reports = self.service.pull_reports()
        self.assertEqual({item.report.report_id for item in reports}, {
            self.report.report_id,
            new_report.report_id,
        })
        revocations = self.coordinator.revocation_list()["revoked_members"]
        self.assertEqual(revocations[0]["member_id"], "member-a")
        self.assertEqual(revocations[0]["effective_epoch"], self.coordinator.current_epoch)

    def test_coordinator_state_round_trip(self) -> None:
        state_path = Path(self.tempdir.name) / "coordinator.json"
        restored = FederationCoordinator(state_path, self.state_key)
        self.assertEqual(restored.active_member_ids(), ("member-a", "member-b"))
        self.assertEqual(restored.current_key(), self.coordinator.current_key())
        json.loads(state_path.read_text(encoding="utf-8"))

    def test_tsa_token_uses_rfc3161_fields(self) -> None:
        payload = b"timestamped payload"
        token = self.tsa.issue(payload)
        value = json.loads(token)

        self.assertEqual(value["type"], "TimeStampResp")
        self.assertEqual(value["status"]["status"], "granted")
        self.assertEqual(value["message_imprint"]["hash_algorithm"], "sha256")
        self.assertTrue(value["serial_number"])
        self.assertTrue(value["nonce"])
        self.assertTrue(self.tsa.verify(token, payload, self.tsa.public_key_pem))
        self.assertFalse(self.tsa.verify(token, b"changed", self.tsa.public_key_pem))

    def test_kafka_broker_replays_messages_by_offset(self) -> None:
        first = self.broker.publish(
            b"FF1.0.first", kind="report", report_id="report-1", epoch=0
        )
        second = self.broker.publish(
            b"FF1.0.second", kind="dispute", report_id="report-1", epoch=0
        )

        messages = self.broker.pull()

        self.assertEqual([message.sequence for message in messages], [0, 1])
        self.assertEqual(self.broker.pull(first.sequence), [second])

    def test_kafka_broker_rejects_unknown_message_kind(self) -> None:
        with self.assertRaises(ValueError):
            self.broker.publish(
                b"FF1.0.invalid", kind="unknown", report_id=None, epoch=0
            )

    def test_kafka_control_topics_are_restricted(self) -> None:
        self.broker.publish_control(TOPIC_REVOCATIONS, {"version": 1})
        self.broker.publish_control(TOPIC_EPOCHS, {"current_epoch": 0})
        with self.assertRaises(ValueError):
            self.broker.publish_control(TOPIC_EVENTS, {})

    def test_revocation_removes_kafka_member_access(self) -> None:
        admin = FakeKafkaAdmin()
        from kafka_broker import KafkaAccessController

        access_controller = KafkaAccessController(
            "broker.test", admin_client_factory=lambda **_kwargs: admin
        )
        coordinator = FederationCoordinator(
            Path(self.tempdir.name) / "access-coordinator.json",
            generate_aes_key(),
            access_controller=access_controller,
        )
        coordinator.register_member("member-a", self.member_a_public)
        coordinator.revoke_member("member-a")

        self.assertEqual(len(admin.deleted_filters), 3)
        self.assertTrue(
            all(item.principal == "User:member-a" for item in admin.deleted_filters)
        )


if __name__ == "__main__":
    unittest.main()
