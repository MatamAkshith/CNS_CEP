from detection_engine import DetectionEngine


def create_packet(timestamp, source_ip, destination_ip, destination_port):
    return {
        "timestamp": timestamp,
        "ip_version": 4,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": destination_port,
        "length": 60,
        "tcp_flags": "S"
    }


engine = DetectionEngine()

source_ip = "192.168.1.50"
destination_ip = "192.168.1.10"


print("\n===== Unified SYN Scan Test =====")

for i, port in enumerate([22, 23, 80, 443, 8080]):

    packet = create_packet(
        timestamp=1000 + i,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=port
    )

    alerts = engine.analyze(packet)

    if alerts:
        print("🚨 ALERTS")
        for alert in alerts:
            print(alert)

print("====================")


print("\n===== Unified SYN Flood Test =====")

engine = DetectionEngine()

for i in range(20):

    packet = create_packet(
        timestamp=2000 + (i * 0.1),
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=443
    )

    alerts = engine.analyze(packet)

    if alerts:
        print("🚨 ALERTS")
        for alert in alerts:
            print(alert)

print("====================")