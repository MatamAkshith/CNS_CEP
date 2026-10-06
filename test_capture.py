from scapy.all import sniff
from packet_parser import parse_packet


def packet_callback(packet):
    data = parse_packet(packet)

    print("--------------------------------")
    print(f"Time       : {data['timestamp']}")
    print(f"Source     : {data['source_ip']}")
    print(f"Destination: {data['destination_ip']}")
    print(f"Protocol   : {data['protocol']}")
    print(f"Src Port   : {data['source_port']}")
    print(f"Dst Port   : {data['destination_port']}")
    print(f"Length     : {data['length']}")
    print(f"TCP Flags  : {data['tcp_flags']}")


print("Starting packet capture...")
print("Press Ctrl+C to stop.")

sniff(prn=packet_callback)