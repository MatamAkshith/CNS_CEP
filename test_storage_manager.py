import os
import tempfile
import unittest

from storage_manager import StorageManager


class TestStorageManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(
            self.temp_dir.name,
            "test_alerts.json"
        )
        self.addCleanup(self.temp_dir.cleanup)


    def test_storage_file_is_created(self):

        StorageManager(self.test_file)

        self.assertTrue(
            os.path.exists(self.test_file)
        )

    def test_new_storage_is_empty(self):

        manager = StorageManager(self.test_file)

        alerts = manager.load_alerts()

        self.assertEqual(alerts, [])

    def test_save_and_load_alerts(self):

        manager = StorageManager(self.test_file)

        alerts = [
            {
                "type": "Possible TCP SYN Port Scan",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.10",
                "ports_scanned": [22, 23, 80],
                "window": 10
            }
        ]

        manager.save_alerts(alerts)

        loaded_alerts = manager.load_alerts()

        self.assertEqual(
            loaded_alerts,
            alerts
        )

    def test_multiple_alerts(self):

        manager = StorageManager(self.test_file)

        alerts = [
            {
                "type": "Possible TCP SYN Port Scan",
                "source_ip": "192.168.1.50"
            },
            {
                "type": "Possible TCP SYN Flood",
                "source_ip": "10.0.0.5"
            }
        ]

        manager.save_alerts(alerts)

        loaded_alerts = manager.load_alerts()

        self.assertEqual(
            len(loaded_alerts),
            2
        )

        self.assertEqual(
            loaded_alerts,
            alerts
        )

    def test_save_single_alert(self):

        manager = StorageManager(self.test_file)

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        manager.save_alert(alert)

        alerts = manager.load_alerts()

        self.assertEqual(
            alerts,
            [alert]
        )
            
    def test_save_multiple_alerts_individually(self):

        manager = StorageManager(self.test_file)

        alert1 = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50"
        }

        alert2 = {
            "type": "Possible TCP SYN Flood",
            "source_ip": "10.0.0.5"
        }

        manager.save_alert(alert1)
        manager.save_alert(alert2)

        alerts = manager.load_alerts()

        self.assertEqual(
            alerts,
            [alert1, alert2]
        )


if __name__ == "__main__":
    unittest.main()