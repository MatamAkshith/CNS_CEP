from scapy.all import IP, TCP
from test_capture import packet_callback


source_ip = "192.168.1.50"
destination_ip = "192.168.1.10"

for i in range(20):

    packet = (
        IP(
            src=source_ip,
            dst=destination_ip
        )
        /
        TCP(
            sport=50000 + i,
            dport=443,
            flags="S"
        )
    )

    print(f"\nSending test SYN packet #{i + 1}")

    packet_callback(packet)