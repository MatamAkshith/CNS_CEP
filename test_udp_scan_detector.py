from udp_scan_detector import UdpScanDetector


def create_packet(
    timestamp,
    source_ip="192.168.1.50",
    destination_ip="192.168.1.10",
    destination_port=53,
    protocol="UDP"
):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol
    }


# --------------------------------------------------
# Test 1: Four unique UDP ports
# Expected: No alert
# --------------------------------------------------

detector = UdpScanDetector()

ports = [53, 67, 123, 161]

for index, port in enumerate(ports):
    alert = detector.analyze(
        create_packet(index, destination_port=port)
    )

assert alert is None

print("Test 1 passed: 4 UDP ports -> no alert")


# --------------------------------------------------
# Test 2: Five unique UDP ports
# Expected: Alert
# --------------------------------------------------

detector = UdpScanDetector()

ports = [53, 67, 123, 161, 500]

alert = None

for index, port in enumerate(ports):
    alert = detector.analyze(
        create_packet(index, destination_port=port)
    )

assert alert is not None
assert alert["type"] == "Possible UDP Port Scan"
assert alert["source_ip"] == "192.168.1.50"
assert alert["destination_ip"] == "192.168.1.10"
assert alert["ports_scanned"] == [53, 67, 123, 161, 500]

print("Test 2 passed: 5 UDP ports -> alert")


# --------------------------------------------------
# Test 3: Duplicate ports
# Expected: No alert
# --------------------------------------------------

detector = UdpScanDetector()

ports = [53, 53, 67, 67, 123, 123]

for index, port in enumerate(ports):
    alert = detector.analyze(
        create_packet(index, destination_port=port)
    )

assert alert is None

print("Test 3 passed: duplicate ports -> no alert")


# --------------------------------------------------
# Test 4: Packets outside time window
# Expected: No alert
# --------------------------------------------------

detector = UdpScanDetector()

ports = [53, 67, 123, 161, 500]

alert = None

for index, port in enumerate(ports):
    timestamp = index * 6

    alert = detector.analyze(
        create_packet(
            timestamp,
            destination_port=port
        )
    )

assert alert is None

print("Test 4 passed: packets outside time window -> no alert")


# --------------------------------------------------
# Test 5: Non-UDP packets
# Expected: No alert
# --------------------------------------------------

detector = UdpScanDetector()

for index, port in enumerate(ports):
    alert = detector.analyze(
        create_packet(
            index,
            destination_port=port,
            protocol="TCP"
        )
    )

    assert alert is None

print("Test 5 passed: non-UDP packets -> no alert")


print("\nAll UDP scan detector tests passed!")