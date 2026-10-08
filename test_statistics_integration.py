import unittest

from alert_manager import AlertManager
from statistics_manager import StatisticsManager


class TestStatisticsIntegration(unittest.TestCase):

    def test_accepted_alert_is_counted(self):

        alert_manager = AlertManager()
        statistics_manager = StatisticsManager()

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        processed_alert = alert_manager.process(alert)

        if processed_alert:
            statistics_manager.process(processed_alert)

        self.assertEqual(
            statistics_manager.get_total_alerts(),
            1
        )

    def test_duplicate_alert_is_not_counted(self):

        alert_manager = AlertManager()
        statistics_manager = StatisticsManager()

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        first_alert = alert_manager.process(alert)

        if first_alert:
            statistics_manager.process(first_alert)

        duplicate_alert = alert_manager.process(alert)

        if duplicate_alert:
            statistics_manager.process(duplicate_alert)

        self.assertEqual(
            statistics_manager.get_total_alerts(),
            1
        )

    def test_different_alert_types_are_counted(self):

        alert_manager = AlertManager()
        statistics_manager = StatisticsManager()

        scan_alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        flood_alert = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        }

        processed_scan = alert_manager.process(scan_alert)

        if processed_scan:
            statistics_manager.process(processed_scan)

        processed_flood = alert_manager.process(flood_alert)

        if processed_flood:
            statistics_manager.process(processed_flood)

        self.assertEqual(
            statistics_manager.get_total_alerts(),
            2
        )

        self.assertEqual(
            statistics_manager.get_alerts_by_type(),
            {
                "Possible TCP SYN Port Scan": 1,
                "Possible TCP SYN Flood": 1
            }
        )


if __name__ == "__main__":
    unittest.main()