import json
import os
import tempfile
import threading
import time
from collections import deque


DEFAULT_CAPTURE_STATE_PATH = "/tmp/packet_sniffer_capture_state.json"


class CaptureStateManager:
    """
    Thread-safe and process-safe manager for live packet capture state.

    COUNTER DEFINITION:
    - total_packets: Represents total network packets successfully parsed and
      processed by the application's packet_callback handler.
    """

    def __init__(self, filepath=None, max_recent_packets=50):
        if filepath is None:
            filepath = DEFAULT_CAPTURE_STATE_PATH
        self.filepath = filepath
        self.max_recent_packets = max_recent_packets
        self._lock = threading.Lock()

        self.status = "stopped"  # "starting", "active", "waiting", "stopped", "error", "inactive"
        self.is_active = False
        self.total_packets = 0
        self.start_time = None
        self.last_packet_time = None
        self.last_heartbeat = None
        self.error = None
        self.recent_packets = deque(maxlen=max_recent_packets)

        # Sync with disk file if present
        self._load_from_disk()

    def start_capture(self):
        with self._lock:
            now = time.time()
            self.status = "starting"
            self.is_active = True
            self.total_packets = 0
            self.start_time = now
            self.last_packet_time = None
            self.last_heartbeat = now
            self.error = None
            self.recent_packets.clear()
            self._save_to_disk_unlocked()

    def touch_heartbeat(self):
        with self._lock:
            if self.is_active:
                self.last_heartbeat = time.time()
                self._save_to_disk_unlocked()

    def record_packet(self, parsed_packet):
        with self._lock:
            now = time.time()

            if not self.is_active:
                self.is_active = True
                if self.start_time is None:
                    self.start_time = now

            self.status = "active"
            self.total_packets += 1
            self.last_heartbeat = now
            self.last_packet_time = parsed_packet.get("timestamp") or time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(now)
            )

            packet_info = {
                "timestamp": self.last_packet_time,
                "protocol": parsed_packet.get("protocol", "Unknown"),
                "source_ip": parsed_packet.get("source_ip", "N/A"),
                "destination_ip": parsed_packet.get("destination_ip", "N/A"),
                "source_port": parsed_packet.get("source_port"),
                "destination_port": parsed_packet.get("destination_port"),
                "length": parsed_packet.get("length"),
                "tcp_flags": parsed_packet.get("tcp_flags"),
            }

            self.recent_packets.append(packet_info)
            self._save_to_disk_unlocked()

    def stop_capture(self):
        with self._lock:
            self.status = "stopped"
            self.is_active = False
            self.last_heartbeat = time.time()
            self._save_to_disk_unlocked()

    def fail_capture(self, error_message):
        with self._lock:
            self.status = "error"
            self.is_active = False
            self.error = str(error_message)
            self.last_heartbeat = time.time()
            self._save_to_disk_unlocked()

    def reset(self):
        with self._lock:
            self.status = "stopped"
            self.is_active = False
            self.total_packets = 0
            self.start_time = None
            self.last_packet_time = None
            self.last_heartbeat = None
            self.error = None
            self.recent_packets.clear()
            self._save_to_disk_unlocked()

    def _save_to_disk(self):
        with self._lock:
            self._save_to_disk_unlocked()

    def _save_to_disk_unlocked(self):
        data = {
            "status": self.status,
            "is_active": self.is_active,
            "total_packets": self.total_packets,
            "start_time": self.start_time,
            "last_packet_time": self.last_packet_time,
            "last_heartbeat": self.last_heartbeat,
            "error": self.error,
            "recent_packets": list(self.recent_packets),
        }
        try:
            temp_path = self.filepath + ".tmp"
            with open(temp_path, "w") as f:
                json.dump(data, f)
            try:
                os.chmod(temp_path, 0o644)
            except Exception:
                pass
            os.replace(temp_path, self.filepath)
            try:
                os.chmod(self.filepath, 0o644)
            except Exception:
                pass
        except Exception:
            pass

    def _load_from_disk(self):
        if not os.path.exists(self.filepath):
            return
        try:
            with open(self.filepath, "r") as f:
                data = json.load(f)
            self.status = data.get("status", "stopped")
            self.is_active = data.get("is_active", False)
            self.total_packets = data.get("total_packets", 0)
            self.start_time = data.get("start_time")
            self.last_packet_time = data.get("last_packet_time")
            self.last_heartbeat = data.get("last_heartbeat")
            self.error = data.get("error")
            raw_packets = data.get("recent_packets", [])
            self.recent_packets = deque(
                raw_packets,
                maxlen=self.max_recent_packets
            )
        except Exception:
            pass

    def get_state(self):
        with self._lock:
            self._load_from_disk()

            now = time.time()
            active = self.is_active
            status = self.status

            if active and self.last_heartbeat is not None:
                if now - self.last_heartbeat > 6.0:
                    active = False
                    status = "inactive"
                elif status == "starting":
                    pass
                elif self.total_packets == 0:
                    status = "waiting"

            duration_seconds = 0
            if self.start_time is not None:
                if active:
                    duration_seconds = int(now - self.start_time)
                elif self.last_heartbeat is not None:
                    duration_seconds = int(self.last_heartbeat - self.start_time)

            return {
                "status": status,
                "is_active": active,
                "total_packets": self.total_packets,
                "start_time": self.start_time,
                "duration_seconds": max(0, duration_seconds),
                "last_packet_time": self.last_packet_time,
                "last_heartbeat": self.last_heartbeat,
                "error": self.error,
                "recent_packets": list(self.recent_packets),
            }



capture_state_manager = CaptureStateManager()


