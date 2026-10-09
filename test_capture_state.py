import os
import tempfile
import time
import unittest

from capture_state import CaptureStateManager


class TestCaptureStateManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(
            self.temp_dir.name,
            "test_capture_state.json"
        )
        self.manager = CaptureStateManager(filepath=self.state_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initial_state(self):
        state = self.manager.get_state()
        self.assertEqual(state["status"], "stopped")
        self.assertFalse(state["is_active"])
        self.assertEqual(state["total_packets"], 0)
        self.assertEqual(state["recent_packets"], [])
        self.assertIsNone(state["error"])

    def test_start_and_stop_capture(self):
        self.manager.start_capture()
        state = self.manager.get_state()
        self.assertEqual(state["status"], "starting")
        self.assertTrue(state["is_active"])
        self.assertIsNotNone(state["start_time"])

        self.manager.record_packet({
            "timestamp": "2026-10-09 10:45:00",
            "protocol": "TCP",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "source_port": 1000,
            "destination_port": 80,
            "length": 60
        })
        state = self.manager.get_state()
        self.assertEqual(state["status"], "active")

        self.manager.stop_capture()
        state = self.manager.get_state()
        self.assertEqual(state["status"], "stopped")
        self.assertFalse(state["is_active"])


    def test_fail_capture(self):
        self.manager.fail_capture("Socket permission denied")
        state = self.manager.get_state()
        self.assertEqual(state["status"], "error")
        self.assertFalse(state["is_active"])
        self.assertEqual(state["error"], "Socket permission denied")

    def test_record_packet(self):
        self.manager.start_capture()
        packet_sample = {
            "timestamp": "2026-10-09 10:45:00",
            "protocol": "TCP",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.10",
            "source_port": 54321,
            "destination_port": 80,
            "length": 64,
            "tcp_flags": "S"
        }

        self.manager.record_packet(packet_sample)
        state = self.manager.get_state()

        self.assertEqual(state["total_packets"], 1)
        self.assertEqual(state["last_packet_time"], "2026-10-09 10:45:00")
        self.assertEqual(len(state["recent_packets"]), 1)
        self.assertEqual(state["recent_packets"][0]["source_ip"], "192.168.1.50")

    def test_bounded_buffer(self):
        self.manager.start_capture()
        for i in range(60):
            packet_sample = {
                "timestamp": f"2026-10-09 10:45:{i:02d}",
                "protocol": "TCP",
                "source_ip": f"192.168.1.{i}",
                "destination_ip": "192.168.1.1",
                "source_port": 1000 + i,
                "destination_port": 80,
                "length": 64,
                "tcp_flags": "S"
            }
            self.manager.record_packet(packet_sample)

        state = self.manager.get_state()
        self.assertEqual(state["total_packets"], 60)
        # Buffer capped at max_recent_packets (50)
        self.assertEqual(len(state["recent_packets"]), 50)
        # Oldest stored packet should be packet 10
        self.assertEqual(state["recent_packets"][0]["source_ip"], "192.168.1.10")
        # Newest stored packet should be packet 59
        self.assertEqual(state["recent_packets"][-1]["source_ip"], "192.168.1.59")

    def test_heartbeat_timeout(self):
        self.manager.start_capture()
        # Artificially age the heartbeat
        self.manager.last_heartbeat = time.time() - 10.0
        self.manager._save_to_disk()

        state = self.manager.get_state()
        self.assertFalse(state["is_active"])
        self.assertEqual(state["status"], "inactive")

    def test_cross_process_file_sync(self):
        # Producer instance
        producer = CaptureStateManager(filepath=self.state_file)
        producer.start_capture()
        producer.record_packet({
            "timestamp": "2026-10-09 10:50:00",
            "protocol": "UDP",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
            "source_port": 5353,
            "destination_port": 53,
            "length": 42
        })

        # Consumer instance (simulating HTTP server process)
        consumer = CaptureStateManager(filepath=self.state_file)
        state = consumer.get_state()

        self.assertEqual(state["status"], "active")
        self.assertEqual(state["total_packets"], 1)
        self.assertEqual(state["recent_packets"][0]["source_ip"], "10.0.0.5")

    def test_thread_safety(self):
        import threading
        self.manager.start_capture()

        def worker():
            for _ in range(50):
                self.manager.record_packet({
                    "timestamp": "2026-10-09 10:55:00",
                    "protocol": "TCP",
                    "source_ip": "192.168.1.100",
                    "destination_ip": "192.168.1.1",
                    "source_port": 12345,
                    "destination_port": 80,
                    "length": 64
                })

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        state = self.manager.get_state()
        self.assertEqual(state["total_packets"], 200)

    def test_http_server_only_does_not_report_active(self):
        # When only the HTTP server runs (with no capture process started),
        # state is stopped or inactive by default.
        state = self.manager.get_state()
        self.assertFalse(state["is_active"])
        self.assertIn(state["status"], ("stopped", "inactive"))

    def test_touch_heartbeat(self):
        self.manager.start_capture()
        initial_hb = self.manager.last_heartbeat
        time.sleep(0.01)
        self.manager.touch_heartbeat()
        state = self.manager.get_state()
        self.assertGreater(state["last_heartbeat"], initial_hb)
        self.assertTrue(state["is_active"])

    def test_default_filepath(self):
        from capture_state import DEFAULT_CAPTURE_STATE_PATH
        self.assertEqual(DEFAULT_CAPTURE_STATE_PATH, "/tmp/packet_sniffer_capture_state.json")


if __name__ == "__main__":
    unittest.main()


