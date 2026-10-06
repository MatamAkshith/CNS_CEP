from scapy.all import IP, IPv6, TCP, UDP, ARP


def parse_packet(packet):
    data = {
        "timestamp": packet.time,
        "ip_version": None,
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "length": len(packet),
        "tcp_flags": None
    }

    # Network Layer / Protocol Identification
    if IP in packet:
        ip_layer = packet[IP]
        data["ip_version"] = 4
        data["source_ip"] = ip_layer.src
        data["destination_ip"] = ip_layer.dst
        data["protocol"] = str(ip_layer.proto)
    elif IPv6 in packet:
        ipv6_layer = packet[IPv6]
        data["ip_version"] = 6
        data["source_ip"] = ipv6_layer.src
        data["destination_ip"] = ipv6_layer.dst
        data["protocol"] = str(ipv6_layer.nh)
    elif ARP in packet:
        arp_layer = packet[ARP]
        data["protocol"] = "ARP"
        data["source_ip"] = arp_layer.psrc
        data["destination_ip"] = arp_layer.pdst

    # Transport Layer Parsing (TCP / UDP)
    if TCP in packet:
        tcp_layer = packet[TCP]
        data["protocol"] = "TCP"
        data["source_port"] = int(tcp_layer.sport)
        data["destination_port"] = int(tcp_layer.dport)
        data["tcp_flags"] = str(tcp_layer.flags)
    elif UDP in packet:
        udp_layer = packet[UDP]
        data["protocol"] = "UDP"
        data["source_port"] = int(udp_layer.sport)
        data["destination_port"] = int(udp_layer.dport)

    return data