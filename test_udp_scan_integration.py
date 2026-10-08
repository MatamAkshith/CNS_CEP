from scapy.all import IP, UDP
from test_capture import packet_callback


source_ip = "192.168.1.50"
destination_ip = "192.168.1.10"

ports = [53, 67, 123, 161, 500]

for port in ports:
    packet = (
        IP(
            src=source_ip,
            dst=destination_ip
        )
        /
        UDP(
            sport=40000,
            dport=port
        )
    )

    packet_callback(packet)