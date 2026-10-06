import unittest
from scapy.all import IP, IPv6, TCP, UDP, ARP, Ether
from packet_parser import parse_packet


class TestPacketParser(unittest.TestCase):

    def test_ipv4_tcp_packet(self):
        pkt = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=54321, dport=443, flags="S")
        pkt.time = 1700000000.0
        parsed = parse_packet(pkt)

        self.assertEqual(parsed["ip_version"], 4)
        self.assertEqual(parsed["source_ip"], "192.168.1.100")
        self.assertEqual(parsed["destination_ip"], "93.184.216.34")
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["source_port"], 54321)
        self.assertEqual(parsed["destination_port"], 443)
        self.assertIsInstance(parsed["source_port"], int)
        self.assertIsInstance(parsed["destination_port"], int)
        self.assertEqual(parsed["tcp_flags"], "S")
        self.assertGreater(parsed["length"], 0)

    def test_ipv4_udp_packet(self):
        pkt = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        pkt.time = 1700000001.0
        parsed = parse_packet(pkt)

        self.assertEqual(parsed["ip_version"], 4)
        self.assertEqual(parsed["source_ip"], "192.168.1.100")
        self.assertEqual(parsed["destination_ip"], "8.8.8.8")
        self.assertEqual(parsed["protocol"], "UDP")
        self.assertEqual(parsed["source_port"], 5353)
        self.assertEqual(parsed["destination_port"], 53)
        self.assertIsInstance(parsed["source_port"], int)
        self.assertIsInstance(parsed["destination_port"], int)
        self.assertIsNone(parsed["tcp_flags"])

    def test_ipv6_tcp_packet(self):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=40000, dport=80, flags="PA")
        pkt.time = 1700000002.0
        parsed = parse_packet(pkt)

        self.assertEqual(parsed["ip_version"], 6)
        self.assertEqual(parsed["source_ip"], "2001:db8::1")
        self.assertEqual(parsed["destination_ip"], "2001:db8::2")
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["source_port"], 40000)
        self.assertEqual(parsed["destination_port"], 80)
        self.assertIsInstance(parsed["source_port"], int)
        self.assertIsInstance(parsed["destination_port"], int)
        self.assertEqual(parsed["tcp_flags"], "PA")

    def test_ipv6_udp_packet(self):
        pkt = IPv6(src="fe80::1", dst="ff02::1") / UDP(sport=546, dport=547)
        pkt.time = 1700000003.0
        parsed = parse_packet(pkt)

        self.assertEqual(parsed["ip_version"], 6)
        self.assertEqual(parsed["source_ip"], "fe80::1")
        self.assertEqual(parsed["destination_ip"], "ff02::1")
        self.assertEqual(parsed["protocol"], "UDP")
        self.assertEqual(parsed["source_port"], 546)
        self.assertEqual(parsed["destination_port"], 547)
        self.assertIsInstance(parsed["source_port"], int)
        self.assertIsInstance(parsed["destination_port"], int)
        self.assertIsNone(parsed["tcp_flags"])

    def test_arp_packet(self):
        pkt = ARP(psrc="192.168.1.1", pdst="192.168.1.254")
        pkt.time = 1700000004.0
        parsed = parse_packet(pkt)

        self.assertIsNone(parsed["ip_version"])
        self.assertEqual(parsed["source_ip"], "192.168.1.1")
        self.assertEqual(parsed["destination_ip"], "192.168.1.254")
        self.assertEqual(parsed["protocol"], "ARP")
        self.assertIsNone(parsed["source_port"])
        self.assertIsNone(parsed["destination_port"])
        self.assertIsNone(parsed["tcp_flags"])

    def test_unsupported_non_ip_packet(self):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        pkt.time = 1700000005.0
        parsed = parse_packet(pkt)

        self.assertIsNone(parsed["ip_version"])
        self.assertIsNone(parsed["source_ip"])
        self.assertIsNone(parsed["destination_ip"])
        self.assertIsNone(parsed["protocol"])
        self.assertIsNone(parsed["source_port"])
        self.assertIsNone(parsed["destination_port"])
        self.assertIsNone(parsed["tcp_flags"])
        self.assertGreater(parsed["length"], 0)


if __name__ == "__main__":
    unittest.main()
