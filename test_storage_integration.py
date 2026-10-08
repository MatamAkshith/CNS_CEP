import os
import unittest

from alert_manager import AlertManager
from storage_manager import StorageManager


class TestStorageIntegration(unittest.TestCase):

    test_file = "test_alerts.json"

    def setUp(self):

        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def tearDown(self):

        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_accepted_alert_is_stored(self):

        alert_manager = AlertManager()
        storage_manager = StorageManager(self.test_file)

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        processed_alert = alert_manager.process(alert)

        if processed_alert:
            storage_manager.save_alert(processed_alert)

        stored_alerts = storage_manager.load_alerts()

        self.assertEqual(
            stored_alerts,
            [alert]
        )

    def test_duplicate_alert_is_not_stored(self):

        alert_manager = AlertManager()
        storage_manager = StorageManager(self.test_file)

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        first_alert = alert_manager.process(alert)

        if first_alert:
            storage_manager.save_alert(first_alert)

        duplicate_alert = alert_manager.process(alert)

        if duplicate_alert:
            storage_manager.save_alert(duplicate_alert)

        stored_alerts = storage_manager.load_alerts()

        self.assertEqual(
            len(stored_alerts),
            1
        )

    def test_different_alerts_are_stored(self):

        alert_manager = AlertManager()
        storage_manager = StorageManager(self.test_file)

        alert1 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        alert2 = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "10.0.0.5"
        }

        processed_alert1 = alert_manager.process(alert1)

        if processed_alert1:
            storage_manager.save_alert(processed_alert1)

        processed_alert2 = alert_manager.process(alert2)

        if processed_alert2:
            storage_manager.save_alert(processed_alert2)

        stored_alerts = storage_manager.load_alerts()

        self.assertEqual(
            stored_alerts,
            [alert1, alert2]
        )


if __name__ == "__main__":
    unittest.main()