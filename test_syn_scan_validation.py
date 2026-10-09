import unittest

from detection_engine import SynScanDetector


class TestSynScanDetectorValidation(unittest.TestCase):

    def setUp(self):
        self.detector = SynScanDetector()

    def make_packet(
        self,
        timestamp,
        destination_port,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.10",
        protocol="TCP",
        tcp_flags="S"
    ):
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "destination_port": destination_port,
            "tcp_flags": tcp_flags
        }

    def test_four_unique_ports_do_not_trigger_alert(self):
        ports = [22, 23, 80, 443]

        for timestamp, port in enumerate(ports, start=1):
            alert = self.detector.analyze(
                self.make_packet(timestamp, port)
            )

            self.assertIsNone(alert)

    def test_five_unique_ports_trigger_alert(self):
        ports = [22, 23, 80, 443, 8080]
        alert = None

        for timestamp, port in enumerate(ports, start=1):
            alert = self.detector.analyze(
                self.make_packet(timestamp, port)
            )

        self.assertIsNotNone(alert)
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

    def test_repeated_same_port_does_not_trigger_alert(self):
        for timestamp in range(1, 6):
            alert = self.detector.analyze(
                self.make_packet(timestamp, 443)
            )

            self.assertIsNone(alert)

    def test_ports_outside_time_window_do_not_trigger_alert(self):
        packets = [
            (1, 22),
            (2, 23),
            (3, 80),
            (4, 443),
            (15, 8080)
        ]

        for timestamp, port in packets:
            alert = self.detector.analyze(
                self.make_packet(timestamp, port)
            )

            self.assertIsNone(alert)

    def test_different_destinations_are_tracked_independently(self):
        packets = [
            (1, 22, "192.168.1.10"),
            (2, 23, "192.168.1.20"),
            (3, 80, "192.168.1.30"),
            (4, 443, "192.168.1.40"),
            (5, 8080, "192.168.1.50")
        ]

        for timestamp, port, destination in packets:
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp,
                    port,
                    destination_ip=destination
                )
            )

            self.assertIsNone(alert)

    def test_non_syn_tcp_packets_are_ignored(self):
        for timestamp, port in enumerate(
            [22, 23, 80, 443, 8080],
            start=1
        ):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp,
                    port,
                    tcp_flags="A"
                )
            )

            self.assertIsNone(alert)

    def test_non_tcp_packets_are_ignored(self):
        packet = self.make_packet(
            timestamp=1,
            destination_port=443,
            protocol="UDP"
        )

        alert = self.detector.analyze(packet)

        self.assertIsNone(alert)

    def test_missing_required_fields_do_not_crash(self):
        packets = [
            {
                "timestamp": 1,
                "destination_ip": "192.168.1.10",
                "protocol": "TCP",
                "destination_port": 443,
                "tcp_flags": "S"
            },
            {
                "timestamp": 1,
                "source_ip": "192.168.1.50",
                "protocol": "TCP",
                "destination_port": 443,
                "tcp_flags": "S"
            },
            {
                "timestamp": 1,
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "protocol": "TCP",
                "tcp_flags": "S"
            },
            {
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "protocol": "TCP",
                "destination_port": 443,
                "tcp_flags": "S"
            }
        ]

        for packet in packets:
            with self.subTest(packet=packet):
                alert = self.detector.analyze(packet)
                self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()