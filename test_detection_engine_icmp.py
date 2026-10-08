from detection_engine import DetectionEngine


def create_packet(timestamp, destination_ip):
    return {
        "timestamp": timestamp,
        "source_ip": "192.168.1.50",
        "destination_ip": destination_ip,
        "protocol": "ICMP"
    }


engine = DetectionEngine()

destinations = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5"
]

alerts = []

for index, destination in enumerate(destinations):
    packet = create_packet(
        timestamp=index,
        destination_ip=destination
    )

    alerts.extend(engine.analyze(packet))


assert len(alerts) == 1

assert alerts[0]["type"] == "Possible ICMP Host Sweep"

assert alerts[0]["source_ip"] == "192.168.1.50"

assert alerts[0]["hosts_scanned"] == [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5"
]

print("ICMP sweep integration test passed!")
print(alerts[0])