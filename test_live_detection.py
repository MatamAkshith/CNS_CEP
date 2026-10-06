from scapy.all import IP, TCP
from test_capture import packet_callback


source_ip = "192.168.1.50"
destination_ip = "192.168.1.10"

ports = [22, 23, 80, 443, 8080]

for port in ports:

    packet = (
        IP(
            src=source_ip,
            dst=destination_ip
        )
        /
        TCP(
            sport=50000 + port,
            dport=port,
            flags="S"
        )
    )

    print(f"\nSending test SYN packet to port {port}")

    packet_callback(packet)