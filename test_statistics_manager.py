import unittest

from statistics_manager import StatisticsManager


class TestStatisticsManager(unittest.TestCase):

    def test_none_alert_is_ignored(self):

        manager = StatisticsManager()

        manager.process(None)

        self.assertEqual(manager.get_total_alerts(), 0)

    def test_single_alert(self):

        manager = StatisticsManager()

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        manager.process(alert)

        self.assertEqual(manager.get_total_alerts(), 1)

    def test_multiple_alerts(self):

        manager = StatisticsManager()

        alert1 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        alert2 = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "10.0.0.5"
        }

        alert3 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.100"
        }

        manager.process(alert1)
        manager.process(alert2)
        manager.process(alert3)

        self.assertEqual(manager.get_total_alerts(), 3)

    def test_alerts_by_type(self):

        manager = StatisticsManager()

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.60"
        })

        manager.process({
            "type": "Possible TCP SYN Flood",
            "source_ip": "10.0.0.5"
        })

        statistics = manager.get_alerts_by_type()

        expected = {
            "Possible TCP SYN Port Scan": 2,
            "Possible TCP SYN Flood": 1
        }

        self.assertEqual(statistics, expected)

    def test_alerts_by_source(self):

        manager = StatisticsManager()

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "10.0.0.5"
        })

        statistics = manager.get_alerts_by_source()

        expected = {
            "192.168.1.50": 2,
            "10.0.0.5": 1
        }

        self.assertEqual(statistics, expected)

    def test_top_source(self):

        manager = StatisticsManager()

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "10.0.0.5"
        })

        result = manager.get_top_source()

        expected = {
            "source_ip": "192.168.1.50",
            "count": 2
        }

        self.assertEqual(result, expected)

    def test_top_alert_type(self):

        manager = StatisticsManager()

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "10.0.0.5"
        })

        manager.process({
            "type": "Possible TCP SYN Flood",
            "source_ip": "192.168.1.100"
        })

        result = manager.get_top_alert_type()

        expected = {
            "type": "Possible TCP SYN Port Scan",
            "count": 2
        }

        self.assertEqual(result, expected)

    def test_top_source_with_no_alerts(self):

        manager = StatisticsManager()

        self.assertIsNone(
            manager.get_top_source()
        )

    def test_top_alert_type_with_no_alerts(self):

        manager = StatisticsManager()

        self.assertIsNone(
            manager.get_top_alert_type()
        )

        
    def test_summary(self):

        manager = StatisticsManager()

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        })

        manager.process({
            "type": "Possible TCP SYN Flood",
            "source_ip": "10.0.0.5"
        })

        summary = manager.get_summary()

        expected = {
            "total_alerts": 3,
            "alerts_by_type": {
                "Possible TCP SYN Port Scan": 2,
                "Possible TCP SYN Flood": 1
            },
            "alerts_by_source": {
                "192.168.1.50": 2,
                "10.0.0.5": 1
            },
            "top_source": {
                "source_ip": "192.168.1.50",
                "count": 2
            },
            "top_alert_type": {
                "type": "Possible TCP SYN Port Scan",
                "count": 2
            }
        }

        self.assertEqual(summary, expected)


if __name__ == "__main__":
    unittest.main()