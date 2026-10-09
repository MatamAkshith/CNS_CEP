import unittest

from syn_flood_detector import SynFloodDetector


class TestSynFloodValidation(unittest.TestCase):

    def setUp(self):
        self.detector = SynFloodDetector()

    def make_packet(
        self,
        timestamp=1,
        source_ip="192.168.1.50",
        protocol="TCP",
        tcp_flags="S",
        destination_port=443
    ):
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": "192.168.1.10",
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "destination_port": destination_port
        }

    def test_nineteen_syn_packets_do_not_trigger_alert(self):
        for i in range(19):
            packet = self.make_packet(timestamp=i * 0.2)
            alert = self.detector.analyze(packet)

            self.assertIsNone(alert)

    def test_twenty_syn_packets_within_window_trigger_alert(self):
        alert = None

        for i in range(20):
            packet = self.make_packet(timestamp=i * 0.2)
            alert = self.detector.analyze(packet)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "Possible TCP SYN Flood")
        self.assertEqual(alert["source_ip"], "192.168.1.50")
        self.assertEqual(alert["syn_count"], 20)
        self.assertEqual(alert["window"], 5)

    def test_syn_packets_outside_window_do_not_trigger_alert(self):
        alert = None

        for i in range(20):
            packet = self.make_packet(timestamp=i * 6)
            alert = self.detector.analyze(packet)

        self.assertIsNone(alert)

    def test_non_syn_tcp_packets_are_ignored(self):
        packets = [
            self.make_packet(timestamp=1, tcp_flags="A"),
            self.make_packet(timestamp=2, tcp_flags="SA"),
            self.make_packet(timestamp=3, tcp_flags="F"),
        ]

        for packet in packets:
            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})

    def test_udp_packets_are_ignored(self):
        for i in range(20):
            packet = self.make_packet(
                timestamp=i * 0.1,
                protocol="UDP",
                tcp_flags=None
            )

            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})

    def test_source_ips_are_tracked_independently(self):
        for i in range(10):
            packet_a = self.make_packet(
                timestamp=i * 0.1,
                source_ip="192.168.1.50"
            )
            packet_b = self.make_packet(
                timestamp=i * 0.1,
                source_ip="192.168.1.60"
            )

            self.assertIsNone(self.detector.analyze(packet_a))
            self.assertIsNone(self.detector.analyze(packet_b))

        self.assertEqual(len(self.detector.tracker["192.168.1.50"]), 10)
        self.assertEqual(len(self.detector.tracker["192.168.1.60"]), 10)

    def test_missing_required_fields_do_not_crash(self):
        packets = [
            {
                "timestamp": 1,
                "protocol": "TCP",
                "tcp_flags": "S"
            },
            {
                "source_ip": "192.168.1.50",
                "protocol": "TCP",
                "tcp_flags": "S"
            },
            {
                "source_ip": None,
                "timestamp": 1,
                "protocol": "TCP",
                "tcp_flags": "S"
            },
            {
                "source_ip": "192.168.1.50",
                "timestamp": None,
                "protocol": "TCP",
                "tcp_flags": "S"
            }
        ]

        for packet in packets:
            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})

    def test_repeated_destination_port_still_counts_packets(self):
        alert = None

        for i in range(20):
            packet = self.make_packet(
                timestamp=i * 0.2,
                destination_port=443
            )
            alert = self.detector.analyze(packet)

        self.assertIsNotNone(alert)
        self.assertEqual(alert["syn_count"], 20)


if __name__ == "__main__":
    unittest.main()