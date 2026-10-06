from scapy.all import sniff
from packet_parser import parse_packet


def packet_callback(packet):
    data = parse_packet(packet)

    print("========================================")
    print(f"Timestamp       : {data['timestamp']}")
    print(f"IP Version      : {data['ip_version']}")
    print(f"Source          : {data['source_ip']}")
    print(f"Destination     : {data['destination_ip']}")
    print(f"Protocol        : {data['protocol']}")
    print(f"Source Port     : {data['source_port']}")
    print(f"Destination Port: {data['destination_port']}")
    print(f"Length          : {data['length']}")
    print(f"TCP Flags       : {data['tcp_flags']}")
    print("========================================")


if __name__ == "__main__":
    print("Starting live packet capture...")
    print("Press Ctrl+C to stop.")

    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        print("\nPacket capture stopped cleanly.")