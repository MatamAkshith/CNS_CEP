from icmp_sweep_detector import IcmpSweepDetector


def create_packet(
    timestamp,
    source_ip="192.168.1.50",
    destination_ip="192.168.1.1",
    protocol="ICMP"
):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol
    }


# --------------------------------------------------
# Test 1: Four unique destinations
# Expected: No alert
# --------------------------------------------------

detector = IcmpSweepDetector()

destinations = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4"
]

for index, destination in enumerate(destinations):
    alert = detector.analyze(
        create_packet(
            index,
            destination_ip=destination
        )
    )

assert alert is None

print("Test 1 passed: 4 hosts -> no alert")


# --------------------------------------------------
# Test 2: Five unique destinations
# Expected: Alert
# --------------------------------------------------

detector = IcmpSweepDetector()

destinations = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5"
]

alert = None

for index, destination in enumerate(destinations):
    alert = detector.analyze(
        create_packet(
            index,
            destination_ip=destination
        )
    )

assert alert is not None
assert alert["type"] == "Possible ICMP Host Sweep"
assert alert["source_ip"] == "192.168.1.50"
assert alert["hosts_scanned"] == destinations
assert alert["window"] == 10

print("Test 2 passed: 5 hosts -> alert")


# --------------------------------------------------
# Test 3: Duplicate destinations
# Expected: No alert
# --------------------------------------------------

detector = IcmpSweepDetector()

destinations = [
    "192.168.1.1",
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.3"
]

for index, destination in enumerate(destinations):
    alert = detector.analyze(
        create_packet(
            index,
            destination_ip=destination
        )
    )

assert alert is None

print("Test 3 passed: duplicate destinations -> no alert")


# --------------------------------------------------
# Test 4: Packets outside time window
# Expected: No alert
# --------------------------------------------------

detector = IcmpSweepDetector()

destinations = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5"
]

for index, destination in enumerate(destinations):
    alert = detector.analyze(
        create_packet(
            index * 6,
            destination_ip=destination
        )
    )

assert alert is None

print("Test 4 passed: packets outside time window -> no alert")


# --------------------------------------------------
# Test 5: Non-ICMP traffic
# Expected: No alert
# --------------------------------------------------

detector = IcmpSweepDetector()

for index, destination in enumerate(destinations):
    alert = detector.analyze(
        create_packet(
            index,
            destination_ip=destination,
            protocol="TCP"
        )
    )

    assert alert is None

print("Test 5 passed: non-ICMP packets -> no alert")


print("\nAll ICMP sweep detector tests passed!")