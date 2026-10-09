import json
import os
import tempfile
import unittest

from scapy.all import IP, TCP

from packet_parser import parse_packet
from detection_engine import DetectionEngine
from alert_manager import AlertManager
from statistics_manager import StatisticsManager
from storage_manager import StorageManager


class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        # Create isolated storage for each test.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = os.path.join(
            self.temp_dir.name,
            "test_alerts.json"
        )

        self.detection_engine = DetectionEngine()
        self.alert_manager = AlertManager()
        self.statistics_manager = StatisticsManager()
        self.storage_manager = StorageManager(self.storage_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def process_packet(self, packet):
        # Stage 1: Parse the raw Scapy packet.
        parsed_packet = parse_packet(packet)

        # Stage 2: Run all detection algorithms.
        alerts = self.detection_engine.analyze(parsed_packet)

        accepted_alerts = []

        # Stage 3: Deduplicate, update statistics, and persist.
        for alert in alerts:
            processed_alert = self.alert_manager.process(alert)

            if processed_alert:
                self.statistics_manager.process(processed_alert)
                self.storage_manager.save_alert(processed_alert)
                accepted_alerts.append(processed_alert)

        return parsed_packet, accepted_alerts

    def create_syn_packet(self, destination_port, timestamp):
        packet = (
            IP(
                src="192.168.1.50",
                dst="192.168.1.10"
            )
            / TCP(
                sport=50000,
                dport=destination_port,
                flags="S"
            )
        )

        # Scapy's parser uses packet.time.
        packet.time = timestamp

        return packet

    def test_complete_syn_scan_pipeline(self):
        # Send four SYN packets to different ports.
        for index, port in enumerate([22, 23, 80, 443]):
            packet = self.create_syn_packet(
                destination_port=port,
                timestamp=1000 + index
            )

            _, alerts = self.process_packet(packet)

            self.assertEqual(
                len(alerts),
                0,
                "An alert should not occur before the fifth unique port."
            )

        # The fifth unique destination port should trigger an alert.
        packet = self.create_syn_packet(
            destination_port=8080,
            timestamp=1004
        )

        parsed_packet, alerts = self.process_packet(packet)

        # Verify packet parsing.
        self.assertEqual(parsed_packet["protocol"], "TCP")
        self.assertEqual(parsed_packet["source_ip"], "192.168.1.50")
        self.assertEqual(parsed_packet["destination_ip"], "192.168.1.10")
        self.assertEqual(parsed_packet["destination_port"], 8080)
        self.assertEqual(parsed_packet["tcp_flags"], "S")

        # Verify detection.
        self.assertEqual(len(alerts), 1)

        alert = alerts[0]

        self.assertEqual(
            alert["type"],
            "Possible TCP SYN Port Scan"
        )
        self.assertEqual(
            alert["source_ip"],
            "192.168.1.50"
        )
        self.assertEqual(
            alert["destination_ip"],
            "192.168.1.10"
        )
        self.assertEqual(
            alert["ports_scanned"],
            [22, 23, 80, 443, 8080]
        )

        # Verify alert management.
        self.assertEqual(
            len(self.alert_manager.get_alerts()),
            1
        )

        # Verify statistics.
        self.assertEqual(
            self.statistics_manager.get_total_alerts(),
            1
        )

        self.assertEqual(
            self.statistics_manager.get_alerts_by_type(),
            {"Possible TCP SYN Port Scan": 1}
        )

        # Verify persistence.
        stored_alerts = self.storage_manager.load_alerts()

        self.assertEqual(len(stored_alerts), 1)
        self.assertEqual(
            stored_alerts[0]["type"],
            "Possible TCP SYN Port Scan"
        )

        # Send another packet that causes the detector to report
        # the same alert type from the same source.
        packet = self.create_syn_packet(
            destination_port=8443,
            timestamp=1005
        )

        _, duplicate_alerts = self.process_packet(packet)

        # AlertManager should reject the duplicate.
        self.assertEqual(len(duplicate_alerts), 0)

        # Statistics and storage must remain unchanged.
        self.assertEqual(
            self.statistics_manager.get_total_alerts(),
            1
        )

        self.assertEqual(
            len(self.storage_manager.load_alerts()),
            1
        )


if __name__ == "__main__":
    unittest.main()