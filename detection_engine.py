class SynScanDetector:

    def __init__(self, time_window=10, port_threshold=5):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.tracker = {}

    def analyze(self, packet):

        # Only analyze TCP packets
        if packet.get("protocol") != "TCP":
            return None

        # Only analyze initial SYN packets
        if packet.get("tcp_flags") != "S":
            return None

        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        destination_port = packet.get("destination_port")
        timestamp = packet.get("timestamp")

        # Make sure required information exists
        if (
            source_ip is None
            or destination_ip is None
            or destination_port is None
            or timestamp is None
        ):
            return None

        # Track each source-destination pair independently
        connection = (source_ip, destination_ip)

        if connection not in self.tracker:
            self.tracker[connection] = []

        # Store this SYN request
        self.tracker[connection].append(
            (timestamp, destination_port)
        )

        # Remove packets outside the time window
        self.tracker[connection] = [
            entry
            for entry in self.tracker[connection]
            if timestamp - entry[0] <= self.time_window
        ]

        # Get unique destination ports
        unique_ports = set(
            entry[1]
            for entry in self.tracker[connection]
        )

        # Check whether threshold has been reached
        if len(unique_ports) >= self.port_threshold:
            return {
                "type": "Possible TCP SYN Port Scan",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ports_scanned": sorted(unique_ports),
                "window": self.time_window
            }

        return None