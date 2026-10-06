from detection_engine import SynScanDetector


def test_detector(name, packets):
    print(f"\n===== {name} =====")

    detector = SynScanDetector()

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
        "tcp_flags": "S"
    }
]

test_detector("Normal TCP Traffic", normal_traffic)


# Test 2: Same port repeated multiple times
repeated_port = [
    {
        "timestamp": i,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    }
    for i in range(1, 6)
]

test_detector("Repeated Same Port", repeated_port)


# Test 3: Five unique ports within 10 seconds
port_scan = [
    {
        "timestamp": 1,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 22,
        "tcp_flags": "S"
    },
    {
        "timestamp": 2,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 23,
        "tcp_flags": "S"
    },
    {
        "timestamp": 3,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 80,
        "tcp_flags": "S"
    },
    {
        "timestamp": 4,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    },
    {
        "timestamp": 5,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 8080,
        "tcp_flags": "S"
    }
]

test_detector("TCP SYN Port Scan", port_scan)


# Test 4: Five ports outside the 10-second window
outside_window = [
    {
        "timestamp": 1,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 22,
        "tcp_flags": "S"
    },
    {
        "timestamp": 2,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 23,
        "tcp_flags": "S"
    },
    {
        "timestamp": 3,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 80,
        "tcp_flags": "S"
    },
    {
        "timestamp": 4,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    },
    {
        "timestamp": 15,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 8080,
        "tcp_flags": "S"
    }
]

test_detector("Ports Outside Time Window", outside_window)


# Test 5: Same source scanning different destinations

different_destinations = [
    {
        "timestamp": 1,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "destination_port": 22,
        "tcp_flags": "S"
    },
    {
        "timestamp": 2,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.20",
        "protocol": "TCP",
        "destination_port": 23,
        "tcp_flags": "S"
    },
    {
        "timestamp": 3,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.30",
        "protocol": "TCP",
        "destination_port": 80,
        "tcp_flags": "S"
    },
    {
        "timestamp": 4,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.40",
        "protocol": "TCP",
        "destination_port": 443,
        "tcp_flags": "S"
    },
    {
        "timestamp": 5,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.50",
        "protocol": "TCP",
        "destination_port": 8080,
        "tcp_flags": "S"
    }
]

test_detector("Different Destinations", different_destinations)