import os
import unittest

from storage_manager import StorageManager


class TestStoragePersistence(unittest.TestCase):

    test_file = "test_alerts.json"

    def setUp(self):

        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def tearDown(self):

        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_alerts_survive_new_storage_manager(self):

        first_manager = StorageManager(self.test_file)

        alert = {
            "type": "Possible TCP SYN Port Scan",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.10",
            "ports_scanned": [22, 23, 80, 443, 8080],
            "window": 10
        }

        first_manager.save_alert(alert)

        second_manager = StorageManager(self.test_file)

        stored_alerts = second_manager.load_alerts()

        self.assertEqual(
            stored_alerts,
            [alert]
        )


if __name__ == "__main__":
    unittest.main()
    