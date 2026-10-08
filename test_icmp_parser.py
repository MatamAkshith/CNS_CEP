from scapy.all import IP, ICMP
from packet_parser import parse_packet


packet = (
    IP(
        src="192.168.1.50",
        dst="192.168.1.10"
    )
    /
    ICMP()
)

parsed_packet = parse_packet(packet)

print(parsed_packet)

assert parsed_packet["protocol"] == "ICMP"
assert parsed_packet["source_ip"] == "192.168.1.50"
assert parsed_packet["destination_ip"] == "192.168.1.10"

print("ICMP parser test passed!")