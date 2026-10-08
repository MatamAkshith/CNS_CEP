from scapy.all import IP, ICMP
from test_capture import packet_callback


source_ip = "192.168.1.50"

destinations = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4",
    "192.168.1.5"
]

for destination_ip in destinations:
    packet = (
        IP(
            src=source_ip,
            dst=destination_ip
        )
        /
        ICMP()
    )

    packet_callback(packet)
    