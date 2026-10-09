import unittest

from udp_scan_detector import UdpScanDetector


class TestUDPScanValidation(unittest.TestCase):

    def setUp(self):
        self.detector = UdpScanDetector()

    def make_packet(
        self,
        timestamp=1,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.10",
        destination_port=53,
        protocol="UDP"
    ):
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol
        }

    def test_four_unique_ports_do_not_trigger_alert(self):
        ports = [53, 67, 123, 161]

        for i, port in enumerate(ports):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_port=port
                )
            )

            self.assertIsNone(alert)

    def test_five_unique_ports_trigger_alert(self):
        ports = [53, 67, 123, 161, 500]
        alert = None

        for i, port in enumerate(ports):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_port=port
                )
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "Possible UDP Port Scan")
        self.assertEqual(alert["source_ip"], "192.168.1.50")
        self.assertEqual(alert["destination_ip"], "192.168.1.10")
        self.assertEqual(
            alert["ports_scanned"],
            [53, 67, 123, 161, 500]
        )
        self.assertEqual(alert["window"], 10)

    def test_duplicate_ports_do_not_count_as_unique_ports(self):
        ports = [53, 53, 67, 67, 123, 123]

        for i, port in enumerate(ports):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_port=port
                )
            )

            self.assertIsNone(alert)

    def test_packets_outside_time_window_do_not_trigger_alert(self):
        ports = [53, 67, 123, 161, 500]

        for i, port in enumerate(ports):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i * 6,
                    destination_port=port
                )
            )

            self.assertIsNone(alert)

    def test_non_udp_packets_are_ignored(self):
        for i in range(20):
            packet = self.make_packet(
                timestamp=i * 0.1,
                destination_port=53 + i,
                protocol="TCP"
            )

            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})

    def test_destination_ips_are_tracked_independently(self):
        # Three ports scanned on destination A.
        for i, port in enumerate([53, 67, 123]):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_ip="192.168.1.10",
                    destination_port=port
                )
            )

            self.assertIsNone(alert)

        # Two ports scanned on destination B.
        for i, port in enumerate([161, 500]):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i + 3,
                    destination_ip="192.168.1.20",
                    destination_port=port
                )
            )

            self.assertIsNone(alert)

        self.assertEqual(len(self.detector.tracker), 2)

    def test_source_ips_are_tracked_independently(self):
        for i, port in enumerate([53, 67, 123]):
            packet_a = self.make_packet(
                timestamp=i,
                source_ip="192.168.1.50",
                destination_port=port
            )

            packet_b = self.make_packet(
                timestamp=i,
                source_ip="192.168.1.60",
                destination_port=port
            )

            self.assertIsNone(self.detector.analyze(packet_a))
            self.assertIsNone(self.detector.analyze(packet_b))

        self.assertEqual(
            len(self.detector.tracker[("192.168.1.50", "192.168.1.10")]),
            3
        )
        self.assertEqual(
            len(self.detector.tracker[("192.168.1.60", "192.168.1.10")]),
            3
        )

    def test_missing_required_fields_do_not_crash(self):
        packets = [
            {
                "timestamp": 1,
                "destination_ip": "192.168.1.10",
                "destination_port": 53,
                "protocol": "UDP"
            },
            {
                "timestamp": 1,
                "source_ip": "192.168.1.50",
                "destination_port": 53,
                "protocol": "UDP"
            },
            {
                "timestamp": 1,
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "protocol": "UDP"
            },
            {
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "destination_port": 53,
                "protocol": "UDP"
            }
        ]

        for packet in packets:
            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})


if __name__ == "__main__":
    unittest.main()