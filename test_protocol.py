import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from broker import LocalBroker
from coordinator import FederationCoordinator
from federation_service import FederationService
from models import IncidentReport
from tsa import TrustedTimestampAuthority
from utils_crypto import generate_rsa_key_pair


class FederationProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.member_a_private, self.member_a_public = generate_rsa_key_pair()
        self.member_b_private, self.member_b_public = generate_rsa_key_pair()
        self.arbiter_private, self.arbiter_public = generate_rsa_key_pair()
        self.tsa = TrustedTimestampAuthority()
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.coordinator = FederationCoordinator(root / "coordinator.json")
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
        restored = FederationCoordinator(state_path)
        self.assertEqual(restored.active_member_ids(), ("member-a", "member-b"))
        self.assertEqual(restored.current_key(), self.coordinator.current_key())
        json.loads(state_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
