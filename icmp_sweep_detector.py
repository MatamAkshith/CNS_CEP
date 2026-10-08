class IcmpSweepDetector:
    def __init__(self, time_window=10, host_threshold=5):
        self.time_window = time_window
        self.host_threshold = host_threshold
        self.tracker = {}

    def analyze(self, packet):
        if packet.get("protocol") != "ICMP":
            return None

        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        timestamp = packet.get("timestamp")

        if (
            source_ip is None
            or destination_ip is None
            or timestamp is None
        ):
            return None

        if source_ip not in self.tracker:
            self.tracker[source_ip] = []

        self.tracker[source_ip].append(
            (timestamp, destination_ip)
        )

        self.tracker[source_ip] = [
            entry
            for entry in self.tracker[source_ip]
            if timestamp - entry[0] <= self.time_window
        ]

        unique_destinations = set(
            entry[1]
            for entry in self.tracker[source_ip]
        )

        if len(unique_destinations) >= self.host_threshold:
            return {
                "type": "Possible ICMP Host Sweep",
                "source_ip": source_ip,
                "hosts_scanned": sorted(unique_destinations),
                "window": self.time_window
            }

        return None