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
- IPv4 packet header parsing (Source IP, Destination IP, Protocol ID)
- TCP header parsing (Source Port, Destination Port, TCP Flags)
- UDP header parsing (Source Port, Destination Port - code implemented)
- Basic packet length calculation (`len(packet)`)

### In Progress
- UDP traffic live capture validation
- Non-IP protocol identification and handling (e.g., ARP, Link-Layer frames)

### Not Yet Implemented
- Security detection engine (anomaly & signature-based detection)
- Suspicious port & flag combination detector (e.g., SYN scans, NULL scans, XMAS scans)
- Real-time alert generation system
- Persistent packet logging / PCAP storage
- User interface / Dashboard visualization

---

# Change Log

## 2026-10-06 — Initial Packet Sniffer & Packet Parser Implementation

### Objective
Establish the core live packet capture pipeline and basic packet header parser capable of extracting normalized fields (IPs, Ports, Protocols, Length, TCP Flags) from captured network traffic.

### Why We Did It
Packet sniffing is the foundational requirement for network security monitoring. Before anomaly detection or threat analysis can occur, raw link-layer network packets must be captured from the interface and parsed into structured, normalized Python data structures.

### What Was Changed
- Created `packet_parser.py`:
  - Implemented `parse_packet(packet)` function.
  - Extracted packet timestamp (`packet.time`) and overall packet length (`len(packet)`).
  - Added IPv4 layer check (`IP in packet`) to extract `src` IP, `dst` IP, and IP `proto`.
  - Added TCP layer check (`TCP in packet`) to extract `sport`, `dport`, and stringified `flags`.
  - Added UDP layer check (`UDP in packet`) to extract `sport` and `dport`.
  - Returned structured data dictionary.
- Created `test_capture.py`:
  - Imported `sniff` from `scapy.all` and `parse_packet` from `packet_parser`.
  - Implemented `packet_callback` function to receive captured packets and display normalized output fields.
  - Invoked `sniff(prn=packet_callback)` for continuous live capture.

### Files Changed
- `packet_parser.py`
- `test_capture.py`

### Technical Implementation
Scapy inspects packet layer headers. `IP in packet`, `TCP in packet`, and `UDP in packet` are evaluated sequentially. Extracted header attributes are stored into a standard Python dictionary:

```python
data = {
    "timestamp": packet.time,
    "source_ip": ip_layer.src,
    "destination_ip": ip_layer.dst,
    "protocol": "TCP" / "UDP" / ip_layer.proto,
    "source_port": layer.sport,
    "destination_port": layer.dport,
    "length": len(packet),
    "tcp_flags": str(tcp_layer.flags)
}
```

This decouples lower-level Scapy packet structures from downstream analysis modules.

### Testing Performed
Manual live packet capture test was executed via terminal.
Command run:
```bash
sudo .venv/bin/python test_capture.py
```
Observed behavior:
- Live network interfaces captured active TCP packets (HTTPS, HTTP, local socket traffic).
- Source and Destination IP addresses parsed correctly.
- Source and Destination TCP ports parsed correctly.
- TCP flags (e.g., `PA`, `A`, `S`, `FA`) were formatted and printed accurately.
- Packet length values were extracted successfully.

### Result
Status: SUCCESS (for TCP & IP parsing baseline)

### Limitations / Known Issues
- UDP packet parsing code exists in `packet_parser.py` but has not been verified with live UDP traffic yet.
- Packets lacking an IP layer (e.g. ARP, EAPOL, raw Ethernet frames) yield `None` for IP and protocol fields.
- Non-IPv4 protocols (e.g., IPv6) are not yet handled in the parser logic.

### Git Commit
Commit: 6fe5f8583624c9af5c84bfa685a3cc1cd9376411
Message: feat: add initial packet sniffer implementation
