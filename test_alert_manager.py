import unittest

from alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):

    def test_no_alert(self):
        manager = AlertManager()

        result = manager.process(None)

        self.assertIsNone(result)
        self.assertEqual(manager.get_alerts(), [])

    def test_single_alert(self):
        manager = AlertManager()

        alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50",
            "syn_count": 20,
            "window": 5
        }

        result = manager.process(alert)

        self.assertEqual(result, alert)
        self.assertEqual(len(manager.get_alerts()), 1)
        self.assertEqual(manager.get_alerts()[0], alert)

    def test_multiple_alerts(self):
        manager = AlertManager()

        first_alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        }

        second_alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.60"
        }

        manager.process(first_alert)
        manager.process(second_alert)

        alerts = manager.get_alerts()

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0], first_alert)
        self.assertEqual(alerts[1], second_alert)

    def test_duplicate_alert(self):
        manager = AlertManager()

        alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        }

        first_result = manager.process(alert)
        second_result = manager.process(alert)

        self.assertEqual(first_result, alert)
        self.assertIsNone(second_result)
        self.assertEqual(len(manager.get_alerts()), 1)

    def test_different_alerts_are_not_deduplicated(self):
        manager = AlertManager()

        flood_alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        }

        scan_alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        manager.process(flood_alert)
        manager.process(scan_alert)

        self.assertEqual(len(manager.get_alerts()), 2)

    def test_format_syn_flood_alert(self):
        manager = AlertManager()

        alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50",
            "syn_count": 20,
            "window": 5
        }

        formatted = manager.format_alert(alert)

        self.assertIn("SECURITY ALERT", formatted)
        self.assertIn("Possible TCP SYN Flood", formatted)
        self.assertIn("192.168.1.50", formatted)
        self.assertIn("SYN Count: 20", formatted)
        self.assertIn("Time Window: 5 seconds", formatted)

    def test_format_syn_scan_alert(self):
        manager = AlertManager()

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.10",
            "ports_scanned": [22, 23, 80, 443, 8080],
            "window": 10
        }

        formatted = manager.format_alert(alert)

        self.assertIn("SECURITY ALERT", formatted)
        self.assertIn("Possible TCP SYN Port Scan", formatted)
        self.assertIn("192.168.1.50", formatted)
        self.assertIn("192.168.1.10", formatted)
        self.assertIn("Ports Scanned: [22, 23, 80, 443, 8080]", formatted)
        self.assertIn("Time Window: 10 seconds", formatted)


if __name__ == "__main__":
    unittest.main()