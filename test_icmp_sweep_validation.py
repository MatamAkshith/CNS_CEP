import unittest

from icmp_sweep_detector import IcmpSweepDetector


class TestICMPSweepValidation(unittest.TestCase):

    def setUp(self):
        self.detector = IcmpSweepDetector()

    def make_packet(
        self,
        timestamp=1,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        protocol="ICMP"
    ):
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol
        }

    def test_four_unique_hosts_do_not_trigger_alert(self):
        destinations = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4"
        ]

        for i, destination in enumerate(destinations):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_ip=destination
                )
            )

            self.assertIsNone(alert)

    def test_five_unique_hosts_trigger_alert(self):
        destinations = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5"
        ]

        alert = None

        for i, destination in enumerate(destinations):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_ip=destination
                )
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert["type"], "Possible ICMP Host Sweep")
        self.assertEqual(alert["source_ip"], "192.168.1.50")
        self.assertEqual(alert["hosts_scanned"], destinations)
        self.assertEqual(alert["window"], 10)

    def test_duplicate_destinations_do_not_count_twice(self):
        destinations = [
            "192.168.1.1",
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.3"
        ]

        for i, destination in enumerate(destinations):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i,
                    destination_ip=destination
                )
            )

            self.assertIsNone(alert)

    def test_hosts_outside_time_window_do_not_trigger_alert(self):
        destinations = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5"
        ]

        for i, destination in enumerate(destinations):
            alert = self.detector.analyze(
                self.make_packet(
                    timestamp=i * 6,
                    destination_ip=destination
                )
            )

            self.assertIsNone(alert)

    def test_non_icmp_packets_are_ignored(self):
        for i in range(10):
            packet = self.make_packet(
                timestamp=i,
                destination_ip=f"192.168.1.{i + 1}",
                protocol="TCP"
            )

            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})

    def test_source_ips_are_tracked_independently(self):
        destinations = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3"
        ]

        for i, destination in enumerate(destinations):
            packet_a = self.make_packet(
                timestamp=i,
                source_ip="192.168.1.50",
                destination_ip=destination
            )

            packet_b = self.make_packet(
                timestamp=i,
                source_ip="192.168.1.60",
                destination_ip=destination
            )

            self.assertIsNone(self.detector.analyze(packet_a))
            self.assertIsNone(self.detector.analyze(packet_b))

        self.assertEqual(
            len(self.detector.tracker["192.168.1.50"]),
            3
        )
        self.assertEqual(
            len(self.detector.tracker["192.168.1.60"]),
            3
        )

    def test_missing_required_fields_do_not_crash(self):
        packets = [
            {
                "timestamp": 1,
                "destination_ip": "192.168.1.1",
                "protocol": "ICMP"
            },
            {
                "timestamp": 1,
                "source_ip": "192.168.1.50",
                "protocol": "ICMP"
            },
            {
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.1",
                "protocol": "ICMP"
            },
            {
                "timestamp": None,
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.1",
                "protocol": "ICMP"
            }
        ]

        for packet in packets:
            self.assertIsNone(self.detector.analyze(packet))

        self.assertEqual(self.detector.tracker, {})


if __name__ == "__main__":
    unittest.main()