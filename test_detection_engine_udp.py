from detection_engine import DetectionEngine


def create_packet(timestamp, destination_port):
    return {
        "timestamp": timestamp,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "UDP",
        "destination_port": destination_port
    }


engine = DetectionEngine()

ports = [53, 67, 123, 161, 500]

alerts = []

for index, port in enumerate(ports):
    packet = create_packet(index, port)
    alerts.extend(engine.analyze(packet))


assert len(alerts) == 1

assert alerts[0]["type"] == "Possible UDP Port Scan"

assert alerts[0]["source_ip"] == "192.168.1.50"

assert alerts[0]["destination_ip"] == "192.168.1.10"

assert alerts[0]["ports_scanned"] == [53, 67, 123, 161, 500]

print("UDP scan integration test passed!")
print(alerts[0])