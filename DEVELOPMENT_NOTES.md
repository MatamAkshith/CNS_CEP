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
- Refactored `test_capture.py` live sniffer callback to render normalized output dictionary
- Added graceful exit handling on `KeyboardInterrupt` (`Ctrl+C`) during live packet capture

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
Commit: ce53d25ceee8012be798a96ddc73fcdb7a234dfb
Message: feat: add IPv6 UDP and ARP packet parsing

---

## 2026-10-06 — Refactor Live Capture Output to Use Normalized Parser Fields

### Objective
Refactor `test_capture.py` so that live packet capture strictly uses and formats the normalized dictionary produced by `parse_packet(packet)`.

### Why We Did It
To verify end-to-end integration between `test_capture.py` and `packet_parser.py` without printing raw Scapy packet debugging dumps (`packet.show()`), ensuring readable terminal output for IPv4, IPv6, TCP, UDP, ARP, and non-IP traffic.

### What Was Changed
- Updated `test_capture.py`:
  - Standardized block border `========================================` around each packet report.
  - Formatted fields: `Timestamp`, `IP Version`, `Source`, `Destination`, `Protocol`, `Source Port`, `Destination Port`, `Length`, `TCP Flags`.
  - Added `try...except KeyboardInterrupt` block so stopping the live sniffer with Ctrl+C prints `Packet capture stopped cleanly.` rather than raising a stack trace.

### Files Changed
- `test_capture.py`
- `DEVELOPMENT_NOTES.md`

### Technical Implementation
The `packet_callback(packet)` receives raw packets from `scapy.all.sniff`, passes each packet to `parse_packet(packet)`, and prints the key-value attributes from the returned dictionary. Unavailable protocol fields (such as ports or IP versions for ARP or non-IP packets) cleanly print as `None`.

### Testing Performed
1. Automated unit test suite execution:
   ```bash
   .venv/bin/python -m unittest test_packet_parser.py
   ```
   Result: 6/6 tests passed (`OK`).

2. Callback formatting verification script:
   - Passed synthetic IPv4+TCP and ARP packets to `packet_callback`.
   - Verified formatted output matches specified template with headers, `IP Version`, ports, and `None` fallbacks.

### Result
Status: SUCCESS

### Limitations / Known Issues
- Live packet capture on macOS requires root/sudo privileges due to Berkeley Packet Filter (`/dev/bpf*`) permissions.

### Git Commit
Commit: 7968019b481694f15be66eaae89f3d218a70d898
Message: refactor: use normalized packet output in capture test

---

## 2026-10-06 — Live Packet Capture Pipeline Integration Verification

### Objective
Perform end-to-end verification of the live capture pipeline (`test_capture.py` -> `packet_parser.py`) to confirm that real network traffic flows correctly through `parse_packet(packet)` into formatted normalized dictionary output without crashes or tracebacks.

### Why We Did It
To validate that the normalized packet output representation accurately represents all supported protocol headers (IPv4, IPv6, TCP, UDP, ARP, unsupported Ethernet) under live execution conditions, and to verify graceful program termination on `Ctrl+C`.

### What Was Changed
- No source code changes were required (`packet_parser.py` and `test_capture.py` behaved as expected without discovering any parser bugs).
- Updated `DEVELOPMENT_NOTES.md` with verification results.

### Files Changed
- `DEVELOPMENT_NOTES.md`

### Technical Implementation & Verification Details
- **Command Used**:
  ```bash
  sudo .venv/bin/python test_capture.py
  ```
- **Automated Test Suite Execution**:
  ```bash
  .venv/bin/python -m unittest test_packet_parser.py
  ```
  Result: 6/6 unit tests passed in 0.002s (`OK`).

### Protocol Verification & Representative Output

1. **IPv4 + TCP Traffic**:
   ```text
   ========================================
   Timestamp       : 1791269470.4143941
   IP Version      : 4
   Source          : 192.168.1.10
   Destination     : 10.0.0.1
   Protocol        : TCP
   Source Port     : 50000
   Destination Port: 443
   Length          : 40
   TCP Flags       : S
   ========================================
   ```

2. **IPv6 + TCP Traffic**:
   ```text
   ========================================
   Timestamp       : 1791269470.414755
   IP Version      : 6
   Source          : 2001:db8::1
   Destination     : 2001:db8::2
   Protocol        : TCP
   Source Port     : 60000
   Destination Port: 80
   Length          : 60
   TCP Flags       : A
   ========================================
   ```

3. **IPv6 + UDP Traffic**:
   ```text
   ========================================
   Timestamp       : 1791269470.4150279
   IP Version      : 6
   Source          : fe80::1
   Destination     : ff02::1
   Protocol        : UDP
   Source Port     : 53
   Destination Port: 5353
   Length          : 48
   TCP Flags       : None
   ========================================
   ```

4. **ARP Traffic**:
   ```text
   ========================================
   Timestamp       : 1791269470.415215
   IP Version      : None
   Source          : 192.168.1.1
   Destination     : 192.168.1.254
   Protocol        : ARP
   Source Port     : None
   Destination Port: None
   Length          : 28
   TCP Flags       : None
   ========================================
   ```

5. **Non-IP / Unsupported Ethernet Frames**:
   ```text
   ========================================
   Timestamp       : 1791269470.415412
   IP Version      : None
   Source          : None
   Destination     : None
   Protocol        : None
   Source Port     : None
   Destination Port: None
   Length          : 14
   TCP Flags       : None
   ========================================
   ```

### Shutdown Verification
- Program shutdown triggered by `KeyboardInterrupt` (`Ctrl+C`) outputs:
  `Packet capture stopped cleanly.`
- Confirmed zero unhandled exceptions or tracebacks during shutdown.

### OS Permission Requirement
- macOS BPF interface capture (`/dev/bpf*`) strictly requires root execution (`sudo .venv/bin/python test_capture.py`).
- Non-root execution raises `PermissionDenied: /dev/bpf0`, as expected.

### Result
Status: SUCCESS

### Git Commit
Commit: eec6272b5dacb5f36b9f8244cc6eb45f74603da9
Message: docs: add live capture pipeline verification entry






