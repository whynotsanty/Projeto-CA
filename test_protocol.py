import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from broker import LocalBroker
from broker_network import BrokerHttpClient, BrokerHttpServer
from coordinator import FederationCoordinator
from federation_service import FederationService
from models import IncidentReport
from mqtt_broker import MqttBrokerClient, TOPIC_RELATORIOS
from tsa import TrustedTimestampAuthority
from utils_crypto import generate_rsa_key_pair
from utils_crypto import generate_aes_key


class FakeMqttResult:
    rc = 0


class FakeMqttClient:
    def __init__(self, _client_id: str) -> None:
        self.on_connect = None
        self.on_message = None
        self.published: list[tuple[str, bytes, int]] = []
        self.subscriptions: list[object] = []

    def connect(self, _host: str, _port: int, _keepalive: int) -> None:
        self.on_connect(self, None, {}, 0, None)

    def loop_start(self) -> None:
        return

    def loop_stop(self) -> None:
        return

    def disconnect(self) -> None:
        return

    def subscribe(self, topics: object) -> None:
        self.subscriptions.append(topics)

    def publish(self, topic: str, payload: bytes, qos: int) -> FakeMqttResult:
        self.published.append((topic, payload, qos))
        return FakeMqttResult()

    def receive(self, payload: bytes) -> None:
        message = type("Mensagem", (), {"payload": payload})()
        self.on_message(self, None, message)


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
        self.broker = LocalBroker(root / "broker")
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
        self.tempdir.cleanup()

    def test_publish_pull_and_broker_does_not_see_plaintext(self) -> None:
        message = self.service.publish_report(
            self.report, "member-a", self.member_a_private
        )
        pulled = self.service.pull_reports()

        self.assertEqual(message.sequence, 1)
        self.assertEqual(pulled[0].report, self.report)
        broker_file = next((Path(self.tempdir.name) / "broker").glob("*.json"))
        self.assertNotIn(self.report.to_json(), broker_file.read_bytes())

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

    def test_coordinator_state_round_trip(self) -> None:
        state_path = Path(self.tempdir.name) / "coordinator.json"
        restored = FederationCoordinator(state_path, self.state_key)
        self.assertEqual(restored.active_member_ids(), ("member-a", "member-b"))
        self.assertEqual(restored.current_key(), self.coordinator.current_key())
        json.loads(state_path.read_text(encoding="utf-8"))

    def test_http_broker_publishes_and_pulls_opaque_payloads(self) -> None:
        server = BrokerHttpServer(str(Path(self.tempdir.name) / "http-broker"))
        server.start()
        try:
            host, port = server.address
            client = BrokerHttpClient(host, port)
            message = client.publish(
                b"FF1.0.encrypted", kind="report", report_id=self.report.report_id, epoch=0
            )
            self.assertEqual(client.pull()[0], message)
            self.assertEqual(client.pull()[0].payload, b"FF1.0.encrypted")
        finally:
            server.stop()

    def test_full_service_flow_over_http_broker(self) -> None:
        server = BrokerHttpServer(str(Path(self.tempdir.name) / "service-broker"))
        server.start()
        try:
            host, port = server.address
            service = FederationService(
                self.coordinator,
                BrokerHttpClient(host, port),
                self.arbiter_public,
                self.tsa,
            )
            service.publish_report(self.report, "member-a", self.member_a_private)
            pulled = service.pull_reports()
            self.assertEqual(pulled[0].report, self.report)

            service.publish_corroboration(
                self.report.report_id,
                pulled[0].envelope["linkability_tag"],
                "member-b",
                self.member_b_private,
            )
            self.assertEqual(service.count_corroborations(self.report.report_id), 1)

            dispute = service.publish_dispute(
                self.report.report_id,
                "necessita de verificacao adicional",
                "member-b",
                self.member_b_private,
            )
            self.assertEqual(service.trace_dispute(dispute, self.arbiter_private), "member-b")
        finally:
            server.stop()

    def test_mqtt_adapter_publishes_and_stores_received_messages(self) -> None:
        clientes: list[FakeMqttClient] = []

        def criar_cliente(client_id: str) -> FakeMqttClient:
            cliente = FakeMqttClient(client_id)
            clientes.append(cliente)
            return cliente

        mqtt_broker = MqttBrokerClient(
            Path(self.tempdir.name) / "mqtt-inbox",
            "broker.test",
            mqtt_client_factory=criar_cliente,
        )
        mqtt_broker.connect()
        try:
            mensagem = mqtt_broker.publish(
                b"FF1.0.payload-cifrado",
                kind="report",
                report_id=self.report.report_id,
                epoch=0,
            )
            cliente = clientes[0]
            self.assertEqual(cliente.published[0][0], TOPIC_RELATORIOS)
            self.assertEqual(cliente.published[0][2], 1)
            self.assertEqual(
                tuple(cliente.subscriptions[0]),
                tuple((topic, 1) for topic in mqtt_broker.subscribed_topics),
            )

            recebido = mensagem.to_dict()
            recebido["message_id"] = str(uuid4())
            recebido["sequence"] = 99
            cliente.receive(json.dumps(recebido).encode("utf-8"))
            mensagens = mqtt_broker.pull()
            self.assertEqual(len(mensagens), 2)
        finally:
            mqtt_broker.close()


if __name__ == "__main__":
    unittest.main()
