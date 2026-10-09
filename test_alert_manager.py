import unittest

from alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.manager = AlertManager()

    # --------------------------------------------------
    # Test 1: Process a valid alert
    # --------------------------------------------------

    def test_process_valid_alert(self):
        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        result = self.manager.process(alert)

        self.assertEqual(result, alert)
        self.assertEqual(len(self.manager.get_alerts()), 1)

    # --------------------------------------------------
    # Test 2: Ignore None alert
    # --------------------------------------------------

    def test_process_none_alert(self):
        result = self.manager.process(None)

        self.assertIsNone(result)
        self.assertEqual(len(self.manager.get_alerts()), 0)

    # --------------------------------------------------
    # Test 3: Duplicate alert
    # --------------------------------------------------

    def test_duplicate_alert(self):
        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        first_result = self.manager.process(alert)
        second_result = self.manager.process(alert)

        self.assertEqual(first_result, alert)
        self.assertIsNone(second_result)
        self.assertEqual(len(self.manager.get_alerts()), 1)

    # --------------------------------------------------
    # Test 4: Different alert types are accepted
    # --------------------------------------------------

    def test_different_alert_types(self):
        scan_alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        flood_alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        }

        self.manager.process(scan_alert)
        self.manager.process(flood_alert)

        self.assertEqual(len(self.manager.get_alerts()), 2)

    # --------------------------------------------------
    # Test 5: Different source IPs are accepted
    # --------------------------------------------------

    def test_different_source_ips(self):
        alert_1 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        alert_2 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.60"
        }

        self.manager.process(alert_1)
        self.manager.process(alert_2)

        self.assertEqual(len(self.manager.get_alerts()), 2)

    # --------------------------------------------------
    # Test 6: Format TCP SYN scan alert
    # --------------------------------------------------

    def test_format_alert(self):
        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.10",
            "ports_scanned": [22, 23, 80, 443, 8080],
            "window": 10
        }

        formatted = self.manager.format_alert(alert)

        self.assertIn("🚨 SECURITY ALERT", formatted)
        self.assertIn(
            "Type: Possible TCP SYN Port Scan",
            formatted
        )
        self.assertIn(
            "Source IP: 192.168.1.50",
            formatted
        )
        self.assertIn(
            "Destination IP: 192.168.1.10",
            formatted
        )
        self.assertIn(
            "Ports Scanned: [22, 23, 80, 443, 8080]",
            formatted
        )
        self.assertIn(
            "Time Window: 10 seconds",
            formatted
        )

    # --------------------------------------------------
    # Test 7: Format TCP SYN flood alert
    # --------------------------------------------------

    def test_format_syn_flood_alert(self):
        alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50",
            "syn_count": 20,
            "window": 5
        }

        formatted = self.manager.format_alert(alert)

        self.assertIn(
            "Type: Possible TCP SYN Flood",
            formatted
        )
        self.assertIn(
            "Source IP: 192.168.1.50",
            formatted
        )
        self.assertIn(
            "SYN Count: 20",
            formatted
        )
        self.assertIn(
            "Time Window: 5 seconds",
            formatted
        )

    # --------------------------------------------------
    # Test 8: Format ICMP sweep alert
    # --------------------------------------------------

    def test_format_icmp_sweep_alert(self):
        alert = {
            "type": "Possible ICMP Host Sweep",
            "source_ip": "192.168.1.50",
            "hosts_scanned": [
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.3",
                "192.168.1.4",
                "192.168.1.5"
            ],
            "window": 10
        }

        formatted = self.manager.format_alert(alert)

        self.assertIn(
            "🚨 SECURITY ALERT",
            formatted
        )
        self.assertIn(
            "Type: Possible ICMP Host Sweep",
            formatted
        )
        self.assertIn(
            "Source IP: 192.168.1.50",
            formatted
        )
        self.assertIn(
            "Hosts Scanned:",
            formatted
        )
        self.assertIn(
            "192.168.1.5",
            formatted
        )
        self.assertIn(
            "Time Window: 10 seconds",
            formatted
        )

    # --------------------------------------------------
    # Test 9: Initial alerts seeding deduplicates future alerts
    # --------------------------------------------------

    def test_initial_alerts_deduplication(self):
        initial = [
            {
                "type": "Possible TCP SYN Port Scan",
                "source_ip": "192.168.1.50"
            }
        ]

        seeded_manager = AlertManager(initial)
        self.assertEqual(len(seeded_manager.get_alerts()), 1)

        # Duplicate alert should be rejected
        duplicate_result = seeded_manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })
        self.assertIsNone(duplicate_result)
        self.assertEqual(len(seeded_manager.get_alerts()), 1)

        # New alert type should be accepted
        new_result = seeded_manager.process({
            "type": "Possible UDP Port Scan",
            "source_ip": "192.168.1.50"
        })
        self.assertIsNotNone(new_result)
        self.assertEqual(len(seeded_manager.get_alerts()), 2)


if __name__ == "__main__":
    unittest.main()