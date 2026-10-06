# Development Notes

## Project Overview

This project is a Computer Network Security (CNS) Coursework Enhancement Project (CEP) focused on developing a packet-sniffing and network-security analysis system using Python and Scapy. The system captures live network traffic, extracts and normalizes IP and transport layer packet headers, and provides a foundation for security analysis and anomaly detection.

---

## Current Architecture

```
       Network Interface
               ↓
    Scapy Live Packet Capture
               ↓
        Packet Callback
               ↓
         Packet Parser
               ↓
    Normalized Packet Data
               ↓
        Terminal Output
```

---

# Current Project Status

### Completed
- Python Virtual Environment (`.venv`) and Scapy environment setup
- Live packet capture mechanism using Scapy `sniff()` callback
- macOS BPF permission handling & environment configuration
- Packet normalization parser (`packet_parser.py`)
- IPv4 header parsing (`ip_version = 4`, Source IP, Destination IP, Protocol)
- IPv6 header parsing (`ip_version = 6`, Source IP, Destination IP, Protocol)
- TCP transport header parsing (Source Port, Destination Port, TCP Flags)
- UDP transport header parsing (Source Port, Destination Port, `tcp_flags = None`)
- ARP protocol parsing (`protocol = "ARP"`, `ip_version = None`, Source IP `psrc`, Destination IP `pdst`)
- Numeric port enforcement (`int(sport)`, `int(dport)`) preventing Scapy service name strings
- Non-IP / Unsupported packet handling (safe fallback with `None` fields)
- Automated unit test suite (`test_packet_parser.py` testing 6 protocol combinations)

### In Progress
- Security analysis engine & signature detection planning

### Not Yet Implemented
- Security detection engine (anomaly & signature-based detection)
- Suspicious port & flag combination detector (e.g., SYN scans, NULL scans, XMAS scans)
- Real-time alert generation system
- Persistent packet logging / PCAP storage
- User interface / Dashboard visualization

---

# Change Log

## 2026-10-06 — Add IPv6, UDP, ARP Parsing & IP Version Field Support

### Objective
Expand `packet_parser.py` to support IPv6 (TCP/UDP), IPv4 (TCP/UDP), ARP, and non-IP packets, adding an explicit `ip_version` normalized field, and enforcing numeric port extraction.

### Why We Did It
Diagnostic network capture verified that real-world network traffic contains significant IPv6 traffic, UDP datagrams (e.g., DNS, QUIC), and local ARP broadcasting. Furthermore, Scapy by default translates common port numbers (such as 443) into service strings (`https`), whereas downstream security detectors require strict integer port representations.

### What Was Changed
- Updated `packet_parser.py`:
  - Added imports for `IPv6` and `ARP` from `scapy.all`.
  - Added `ip_version` key to normalized dictionary (`4` for IPv4, `6` for IPv6, `None` for non-IP/ARP).
  - Added `IPv6` layer extraction (`ip_version = 6`, `src`, `dst`, `nh`).
  - Added `ARP` layer extraction (`protocol = "ARP"`, `psrc`, `pdst`, `ip_version = None`).
  - Enforced `int(tcp_layer.sport)` and `int(tcp_layer.dport)` for TCP packets.
  - Enforced `int(udp_layer.sport)` and `int(udp_layer.dport)` for UDP packets with `tcp_flags = None`.
  - Ensured safe fallback returning `None` fields for non-IP / unsupported link-layer frames without crashing.
- Updated `test_capture.py`:
  - Added `IP Version` output line to display normalized output format.
- Created `test_packet_parser.py`:
  - Implemented unit tests covering IPv4+TCP, IPv4+UDP, IPv6+TCP, IPv6+UDP, ARP, and raw Ethernet frames.

### Files Changed
- `packet_parser.py`
- `test_capture.py`
- `test_packet_parser.py`
- `DEVELOPMENT_NOTES.md`

### Technical Implementation
The updated `parse_packet(packet)` evaluates network layer presence using Scapy layer checks (`IP in packet`, `IPv6 in packet`, `ARP in packet`). Transport layer parsing (`TCP in packet`, `UDP in packet`) executes independently to populate ports and flags:

```python
data = {
    "timestamp": packet.time,
    "ip_version": 4 | 6 | None,
    "source_ip": ip_layer.src / psrc / None,
    "destination_ip": ip_layer.dst / pdst / None,
    "protocol": "TCP" | "UDP" | "ARP" | proto_id | None,
    "source_port": int(sport) | None,
    "destination_port": int(dport) | None,
    "length": len(packet),
    "tcp_flags": str(flags) | None
}
```

### Testing Performed
Automated unit test execution:
```bash
.venv/bin/python -m unittest test_packet_parser.py
```
Observed results:
- 6/6 unit tests passed in 0.001s (`OK`).
- IPv4 TCP: `ip_version=4`, `protocol="TCP"`, ports `54321`/`443` (ints), flags `"S"`.
- IPv4 UDP: `ip_version=4`, `protocol="UDP"`, ports `5353`/`53` (ints), `tcp_flags=None`.
- IPv6 TCP: `ip_version=6`, `protocol="TCP"`, ports `40000`/`80` (ints), flags `"PA"`.
- IPv6 UDP: `ip_version=6`, `protocol="UDP"`, ports `546`/`547` (ints), `tcp_flags=None`.
- ARP: `ip_version=None`, `protocol="ARP"`, `source_ip` & `destination_ip` parsed from `psrc`/`pdst`, ports `None`.
- Unsupported Ether: `ip_version=None`, all layer fields `None`, valid `length`.

Diagnostic capture live traffic observation confirmed IPv6 UDP (port 443 numeric) and IPv6 TCP traffic previously.

### Result
Status: SUCCESS

### Limitations / Known Issues
- ICMP / ICMPv6 packets are assigned protocol IDs or default numbers but do not yet have specific ICMP type/code field parsing.
- VLAN tagged frames (802.1Q) are not yet explicitly unpacked before IP layer inspection.

### Git Commit
Commit: 110b81af857ac3d1308ab800d3d2ac3d1c55e8aa
Message: feat: add IPv6 UDP and ARP packet parsing


