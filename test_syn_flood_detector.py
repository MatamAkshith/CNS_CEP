from syn_flood_detector import SynFloodDetector


def test_detector(name, packets):
    print(f"\n===== {name} =====")

    detector = SynFloodDetector()

    for packet in packets:
        alert = detector.analyze(packet)

        if alert:
            print("🚨 SECURITY ALERT")
            print(alert)

    print("====================")


# Test 1: Normal TCP traffic
normal_traffic = [
    {
        "timestamp": 1,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "A"
    }
]

test_detector("Normal TCP Traffic", normal_traffic)


# Test 2: Fewer than threshold
few_syns = [
    {
        "timestamp": i,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    }
    for i in range(1, 20)
]

test_detector("Below SYN Threshold", few_syns)


# Test 3: 20 SYN packets within 5 seconds
syn_flood = [
    {
        "timestamp": i * 0.2,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    }
    for i in range(20)
]

test_detector("TCP SYN Flood", syn_flood)


# Test 4: 20 SYN packets outside the time window
outside_window = [
    {
        "timestamp": i * 6,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    }
    for i in range(20)
]

test_detector("SYNs Outside Time Window", outside_window)


# Test 5: Non-SYN traffic
non_syn_traffic = [
    {
        "timestamp": 1,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "A"
    },
    {
        "timestamp": 2,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "SA"
    },
    {
        "timestamp": 3,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "UDP",
        "destination_port": 443,
        "tcp_flags": None
    }
]

test_detector("Non-SYN Traffic", non_syn_traffic)