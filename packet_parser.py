from scapy.all import IP, TCP, UDP


def parse_packet(packet):
    data = {
        "timestamp": packet.time,
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "length": len(packet),
        "tcp_flags": None
    }

    # Check if packet contains an IP layer
    if IP in packet:
        ip_layer = packet[IP]

        data["source_ip"] = ip_layer.src
        data["destination_ip"] = ip_layer.dst
        data["protocol"] = ip_layer.proto

        # TCP packet
        if TCP in packet:
            tcp_layer = packet[TCP]

            data["protocol"] = "TCP"
            data["source_port"] = tcp_layer.sport
            data["destination_port"] = tcp_layer.dport
            data["tcp_flags"] = str(tcp_layer.flags)

        # UDP packet
        elif UDP in packet:
            udp_layer = packet[UDP]

            data["protocol"] = "UDP"
            data["source_port"] = udp_layer.sport
            data["destination_port"] = udp_layer.dport

    return data