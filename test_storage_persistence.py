import os
import tempfile
import unittest

from storage_manager import StorageManager


class TestStoragePersistence(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(
            self.temp_dir.name,
            "test_alerts.json"
        )
        self.addCleanup(self.temp_dir.cleanup)


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
    