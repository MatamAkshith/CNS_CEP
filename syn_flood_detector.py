class SynFloodDetector:

    def __init__(self, time_window=5, syn_threshold=20):
        self.time_window = time_window
        self.syn_threshold = syn_threshold
        self.tracker = {}

    def analyze(self, packet):

        # Only analyze TCP packets
        if packet.get("protocol") != "TCP":
            return None

        # Only analyze initial SYN packets
        if packet.get("tcp_flags") != "S":
            return None

        source_ip = packet.get("source_ip")
        timestamp = packet.get("timestamp")

        # Make sure required information exists
        if source_ip is None or timestamp is None:
            return None

        # Create tracking information for a new source IP
        if source_ip not in self.tracker:
            self.tracker[source_ip] = []

        # Store this SYN timestamp
        self.tracker[source_ip].append(timestamp)

        # Remove timestamps outside the time window
        self.tracker[source_ip] = [
            packet_time
            for packet_time in self.tracker[source_ip]
            if timestamp - packet_time <= self.time_window
        ]

        # Count SYN packets in the current time window
        syn_count = len(self.tracker[source_ip])

        # Check whether the threshold has been reached
        if syn_count >= self.syn_threshold:
            return {
                "type": "Possible TCP SYN Flood",
                "source_ip": source_ip,
                "syn_count": syn_count,
                "window": self.time_window
            }

        return None