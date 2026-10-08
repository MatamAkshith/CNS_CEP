# Development Notes

## Project Overview

This project is a Computer Network Security (CNS) Coursework Enhancement Project (CEP) focused on developing a packet-sniffing and network-security analysis system using Python and Scapy. The system captures live network traffic, extracts and normalizes IP and transport layer packet headers, and provides a foundation for security analysis and anomaly detection.

---

### Current Architecture

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
        DetectionEngine
    ┌──────────┴──────────┐
    ↓                     ↓
SynScanDetector   SynFloodDetector
(Port Scan)        (Volumetric Flood)
    └──────────┬──────────┘
               ↓
     List of Security Alerts
               ↓
          AlertManager
    ┌──────────┼──────────┐
    ↓          ↓          ↓
 History  Deduplication Formatting
    └──────────┬──────────┘
               ↓
    Human-Readable Console Output
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
- Automated parser unit test suite (`test_packet_parser.py` testing 6 protocol combinations)
- Refactored `test_capture.py` live sniffer callback to render normalized output dictionary
- Graceful exit handling on `KeyboardInterrupt` (`Ctrl+C`) during live packet capture
- Live capture pipeline integration verification (`DEVELOPMENT_NOTES.md`)
- TCP SYN Port Scan Detector module (`detection_engine.py` / `SynScanDetector`)
- Detection engine test suite (`test_detection_engine.py` covering 5 test scenarios)
- Integrated `SynScanDetector` into live capture callback (`test_capture.py`)
- Controlled integration test suite (`test_live_detection.py`) passing synthetic Scapy SYN packets through `packet_callback()`
- TCP SYN Flood Detector module (`syn_flood_detector.py` / `SynFloodDetector`)
- SYN Flood test suite (`test_syn_flood_detector.py` covering 5 test scenarios)
- SYN Flood live capture integration test (`test_syn_flood_integration.py` passing 20 SYN packets to port 443)
- Unified Detection Engine (`detection_engine.py` / `DetectionEngine` class registering `SynScanDetector` & `SynFloodDetector`)
- Updated `test_capture.py` to route normalized packets strictly through `DetectionEngine`
- Unified engine test suite (`test_detection_engine_unified.py` testing both SYN scan and SYN flood detection paths)
- Alert Management Engine (`alert_manager.py` / `AlertManager` class supporting alert history, deduplication, and formatting)
- AlertManager unit test suite (`test_alert_manager.py` with 7 test cases)
- Integrated `AlertManager` into `test_capture.py` capture pipeline

### In Progress
- Phase 9 — Persistent Alert Logging & Storage

### Not Yet Implemented
- Persistent PCAP & Alert storage
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

---

## 2026-10-06 — Implement TCP SYN Port Scan Detector

### Objective
Implement `SynScanDetector` class in `detection_engine.py` to identify potential TCP SYN port scanning attempts by tracking unique destination ports targeted by a source IP within a sliding time window.

### Why We Did It
Port scanning (specifically TCP SYN stealth scanning) is a primary reconnaissance technique used by attackers to discover open network services. Detecting high-frequency connection attempts across multiple ports from a single source address enables early threat warning.

### What Was Changed
- Created `detection_engine.py`:
  - Defined `SynScanDetector` class with configurable `time_window` (default 10s) and `port_threshold` (default 5 ports).
  - Implemented `analyze(packet)` method accepting normalized packet dictionaries.
  - Added filter logic requiring `protocol == "TCP"` and `tcp_flags == "S"`.
  - Added tracking tuple `(source_ip, destination_ip)` mapping to recorded timestamp-port pairs.
  - Added sliding time window cleanup (`timestamp - entry[0] <= self.time_window`).
  - Added unique port set calculation (`set(entry[1] for entry in tracker[connection])`).
  - Generated security alert dictionary when unique ports reach or exceed threshold.
- Created `test_detection_engine.py`:
  - Added 5 test scenarios: Normal TCP Traffic, Repeated Same Port, TCP SYN Port Scan (5 unique ports in 5s), Ports Outside Time Window, and Different Destinations.

### Files Changed
- `detection_engine.py`
- `test_detection_engine.py`
- `DEVELOPMENT_NOTES.md`

### Detection Logic
```python
# Track per (source_ip, destination_ip) pair
connection = (source_ip, destination_ip)
self.tracker[connection].append((timestamp, destination_port))

# Time window filter
self.tracker[connection] = [
    entry for entry in self.tracker[connection]
    if timestamp - entry[0] <= self.time_window
]

# Unique destination port count check
unique_ports = set(entry[1] for entry in self.tracker[connection])
if len(unique_ports) >= self.port_threshold:
    return {
        "type": "Possible TCP SYN Port Scan",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "ports_scanned": sorted(unique_ports),
        "window": self.time_window
    }
```

### Testing Performed
Executed test suite:
```bash
.venv/bin/python test_detection_engine.py
```

Observed test outputs:
1. **Normal TCP Traffic**: No alert generated.
2. **Repeated Same Port** (Port 443 5x): No alert generated (only 1 unique port).
3. **TCP SYN Port Scan** (Ports 22, 23, 80, 443, 8080 within 5s):
   Alert generated: `🚨 SECURITY ALERT {'type': 'Possible TCP SYN Port Scan', 'source_ip': '192.168.1.50', 'destination_ip': '192.168.1.10', 'ports_scanned': [22, 23, 80, 443, 8080], 'window': 10}`
4. **Ports Outside Time Window** (4 ports at t=1..4, 5th port at t=15): No alert generated (window pruned old entries).
5. **Different Destinations**: No alert generated (tracked independently per destination IP).

### Result
Status: SUCCESS

### Limitations / Known Issues
- Currently targets TCP SYN (`"S"`) packets only (does not track NULL, FIN, or XMAS scans yet).
- In-memory state tracking does not persist state across process restarts.

### Git Commit
Commit: 7b783154a109f3082f1e06ce68addaf73982965d
Message: feat: add tcp syn scan detection

---

## 2026-10-06 — Live Detection Integration

### Objective
Integrate the `SynScanDetector` threat detection engine into `test_capture.py`'s live packet capture pipeline so that every captured network packet is parsed and continuously analyzed for TCP SYN port scanning threats in real time.

### Why We Did It
To bridge packet parsing and security analysis, connecting the live capture pipeline directly to the threat detection engine. This ensures security alerts are emitted immediately when a port scanning pattern is detected during live packet capture.

### Architecture & Pipeline
```
Scapy Live sniff()
       ↓
packet_callback(packet)
       ↓
parse_packet(packet)
       ↓
Normalized Packet Dictionary
       ↓
detector.analyze(parsed_packet)
       ↓
Security Alert Output (if threshold met) & Normalized Terminal Display
```

### How Detection Was Integrated
- Modified `test_capture.py`:
  - Created a single persistent instance of `SynScanDetector()` at module level.
  - Updated `packet_callback(packet)` to pass `parsed_packet` to `detector.analyze()`.
  - Added real-time alert printing when `detector.analyze()` returns a non-None alert dictionary.
- Created `test_live_detection.py`:
  - Built controlled integration test harness passing 5 synthetic Scapy SYN packets (ports 22, 23, 80, 443, 8080) through `packet_callback()`.

### Files Changed
- `test_capture.py`
- `test_live_detection.py`
- `DEVELOPMENT_NOTES.md`

### Testing Performed & Results
1. **Controlled Live Integration Test**:
   ```bash
   .venv/bin/python test_live_detection.py
   ```
   **Result**: Packets sent to ports 22, 23, 80, 443 printed normal output blocks. Upon receiving the 5th SYN packet to port 8080, a security alert was generated:
   `🚨 SECURITY ALERT {'type': 'Possible TCP SYN Port Scan', 'source_ip': '192.168.1.50', 'destination_ip': '192.168.1.10', 'ports_scanned': [22, 23, 80, 443, 8080], 'window': 10}`

2. **Detection Engine Test Suite**:
   ```bash
   .venv/bin/python test_detection_engine.py
   ```
   **Result**: 5/5 detection test scenarios passed as expected.

3. **Automated Parser Unit Tests**:
   ```bash
   .venv/bin/python -m unittest test_packet_parser.py
   ```
   **Result**: 6/6 parser unit tests passed in 0.001s (`OK`).

### Result
Status: SUCCESS

### Limitations
- The SYN scan live detection verification used constructed Scapy packets passed directly through `packet_callback()` in `test_live_detection.py` rather than executing an actual live network attack against the local interface.

### Git Commit
Commit: 9fc88c4a42cc1d0592d3ca3f0a1a209729aa30f5
Message: feat: integrate syn scan detection with live capture

---

## 2026-10-06 — TCP SYN Flood Detection

### Objective
Implement `SynFloodDetector` in `syn_flood_detector.py` to identify volumetric Denial of Service (DoS) attempts where an attacker floods a target with high-frequency TCP SYN connection requests from a source IP address within a short time window.

### Detection Rule & Threshold
- **Protocol Rule**: Inspects TCP packets where `tcp_flags == "S"` (initial SYN requests). Ignores non-SYN TCP (e.g. ACK, SYN-ACK) and non-TCP traffic.
- **Tracking Key**: Tracks total SYN packet count independently per `source_ip`.
- **Time Window**: 5-second sliding time window (`timestamp - packet_time <= 5.0`).
- **Threshold**: 20 SYN packets within the 5-second window.
- **Alert Payload**:
  `{'type': 'Possible TCP SYN Flood', 'source_ip': source_ip, 'syn_count': syn_count, 'window': 5}`

### Distinction from SYN Port Scan Detection
- **TCP SYN Port Scan (`SynScanDetector`)**: Tracks unique target destination ports per `(source_ip, destination_ip)` pair (e.g. 5 unique ports targeted within 10s). Designed to detect host reconnaissance across different services.
- **TCP SYN Flood (`SynFloodDetector`)**: Tracks overall SYN packet volume per `source_ip` regardless of destination port (e.g. 20 SYN packets to port 443 within 5s). Designed to detect volumetric connection exhaustion attacks.

### What Was Changed
- Created `syn_flood_detector.py`:
  - Defined `SynFloodDetector` class with default `time_window=5` and `syn_threshold=20`.
  - Implemented `analyze(packet)` maintaining timestamp list per `source_ip` with 5-second sliding window cleanup.
- Created `test_syn_flood_detector.py`:
  - Added 5 unit test cases: Normal TCP Traffic (ACK), Below SYN Threshold (19 SYNs), TCP SYN Flood (20 SYNs in 3.8s -> alert generated), SYNs Outside Time Window (20 SYNs spaced 6s apart -> no alert), and Non-SYN Traffic (ACK, SYN-ACK, UDP).
- Created `test_syn_flood_integration.py`:
  - Built integration test passing 20 synthetic Scapy SYN packets targeting port 443 through `test_capture.py`'s `packet_callback()`.
- Updated `test_capture.py`:
  - Instantiated `flood_detector = SynFloodDetector()` and invoked `flood_detector.analyze(parsed_packet)` inside `packet_callback()` alongside `SynScanDetector`.

### Files Changed
- `syn_flood_detector.py`
- `test_syn_flood_detector.py`
- `test_syn_flood_integration.py`
- `test_capture.py`
- `DEVELOPMENT_NOTES.md`

### Testing Performed & Results
1. **Unit Test Suite Execution**:
   ```bash
   .venv/bin/python test_syn_flood_detector.py
   ```
   **Results**:
   - Normal TCP Traffic (ACK): No alert.
   - Below SYN Threshold (19 SYNs): No alert.
   - TCP SYN Flood (20 SYNs): 🚨 **Security Alert Generated**:
     `{'type': 'Possible TCP SYN Flood', 'source_ip': '192.168.1.50', 'syn_count': 20, 'window': 5}`
   - SYNs Outside Time Window (6s spacing): No alert.
   - Non-SYN Traffic (ACK, SYN-ACK, UDP): No alert.

2. **Integration Test Execution**:
   ```bash
   .venv/bin/python test_syn_flood_integration.py
   ```
   **Results**:
   - 20 synthetic SYN packets targeting port 443 were processed through `packet_callback()`.
   - On the 20th packet, `Possible TCP SYN Flood` alert was generated.
   - **Zero SYN Scan False Positives**: No `Possible TCP SYN Port Scan` alert was generated because all 20 packets targeted a single destination port (443).

3. **Regression Testing**:
   ```bash
   .venv/bin/python test_detection_engine.py
   .venv/bin/python -m unittest test_packet_parser.py
   ```
   **Results**: All detection engine and parser unit tests passed cleanly (`OK`).

### Result
Status: SUCCESS

### Limitations
- The SYN flood integration test used constructed Scapy packets passed directly through `packet_callback()` in `test_syn_flood_integration.py`, NOT an actual live network flooding attack against the network interface.
- In-memory tracker resets state on process restart.

### Git Commit
Commit: 010cb106c35b02f03b2eb10bab6ba509c3a9e740
Message: feat: add tcp syn flood detection

---

## 2026-10-06 — Unified Detection Engine

### Objective
Establish a centralized `DetectionEngine` class in `detection_engine.py` that aggregates and executes all security threat detectors (`SynScanDetector` and `SynFloodDetector`) through a single unified interface.

### Architectural Rationale
Previously, `test_capture.py` directly instantiated and invoked individual detector classes (`SynScanDetector()` and `SynFloodDetector()`). Centralizing detection inside `DetectionEngine`:
1. **Decouples Capture from Detection**: The packet capture callback only interacts with `DetectionEngine.analyze(packet)`, keeping capture logic completely independent of specific detector signatures.
2. **Standardized Alert Aggregation**: `DetectionEngine.analyze(packet)` iterates through all registered detectors, collects any generated non-None alerts into a list `alerts = []`, and returns the list (or an empty list if no threats were detected).
3. **Extensibility**: Future threat detectors (e.g. NULL scan, XMAS scan, UDP sweep) can be registered inside `DetectionEngine` without modifying `test_capture.py` or the packet capture loop.

### DetectionEngine Responsibilities
- Registers detector instances in `self.detectors = [SynScanDetector(), SynFloodDetector()]`.
- Accepts normalized packet dictionaries via `analyze(packet)`.
- Passes the packet to every registered detector sequentially.
- Collects non-None alert dictionaries into a list and returns `alerts`.

### Registered Detectors
1. **`SynScanDetector`**: Detects TCP SYN stealth port scanning (5 unique destination ports per source-destination pair within a 10-second window).
2. **`SynFloodDetector`**: Detects volumetric TCP SYN flood DoS attacks (20 SYN packets per source IP within a 5-second window).

### Change to `test_capture.py`
- Removed direct imports and instantiations of `SynScanDetector` and `SynFloodDetector`.
- Imported and instantiated `detection_engine = DetectionEngine()`.
- Updated `packet_callback(packet)` to call `alerts = detection_engine.analyze(parsed_packet)` and print all alerts returned in the list.

### Unchanged Detection Logic & Thresholds
- `syn_flood_detector.py` was not modified.
- `SynScanDetector` threshold (5 unique ports / 10s) and detection logic were left 100% unchanged.
- `SynFloodDetector` threshold (20 SYNs / 5s) and detection logic were left 100% unchanged.

### Files Changed
- `detection_engine.py`
- `test_capture.py`
- `test_detection_engine_unified.py`
- `DEVELOPMENT_NOTES.md`

### Testing Performed & Results
1. **Compilation Verification**:
   ```bash
   .venv/bin/python -m py_compile detection_engine.py test_capture.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **Unified Engine Test Suite**:
   ```bash
   .venv/bin/python test_detection_engine_unified.py
   ```
   **Result**:
   - SYN Scan Test: Triggered `Possible TCP SYN Port Scan` alert via `DetectionEngine`.
   - SYN Flood Test: Triggered `Possible TCP SYN Flood` alert via `DetectionEngine`.

3. **Regression & Integration Test Suite Execution**:
   - `test_packet_parser.py`: 6/6 tests passed (`OK`).
   - `test_detection_engine.py`: 5/5 SYN scan test scenarios passed.
   - `test_syn_flood_detector.py`: 5/5 SYN flood test scenarios passed.
   - `test_live_detection.py`: 5 SYN packets executed through `packet_callback()`, generating port scan alert on 5th port.
   - `test_syn_flood_integration.py`: 20 SYN packets executed through `packet_callback()`, generating SYN flood alert on 20th packet.

### Result
Status: SUCCESS

### Limitations & Next Steps
- The integration tests (`test_live_detection.py`, `test_syn_flood_integration.py`) used constructed Scapy packets passed through `packet_callback()`, NOT real network attacks.
- Next Phase: **Phase 8 — Alert Management Engine** (centralizing alert formatting, deduplication, and persistent logging).

### Git Commit
Commit: 876ad168019be7506871ea0153919ad0a998246b
Message: feat: unify security detection engine

---

## 2026-10-08 — Alert Management Engine

### Objective
Implement `AlertManager` in `alert_manager.py` to process, deduplicate, store, and format security alerts generated by `DetectionEngine`.

### AlertManager Responsibilities
1. **Alert Processing**: Receives alert dictionaries from `DetectionEngine.analyze()`. Ignores `None` inputs (`process(None)` returns `None`).
2. **Alert History**: Maintains internal list `self.alerts = []` storing all unique processed alerts, retrievable via `get_alerts()`.
3. **Alert Deduplication**: Deduplicates alerts using a composite identity of `alert.get("type")` + `alert.get("source_ip")`. If an alert matching both type and source IP already exists in `self.alerts`, `process()` returns `None` and does not add a duplicate entry.
4. **Human-Readable Formatting**: `format_alert(alert)` converts raw alert dictionaries into structured terminal output strings without modifying the original dictionary contents.

### Deduplication Strategy
- **Identity Key**: `alert type` + `source_ip`.
- **Behavior**: Project-specific first implementation that prevents repetitive console spam when the same source IP triggers multiple alert cycles for the same threat type. Alerts of different types from the same IP (e.g. SYN scan vs SYN flood) or alerts from different source IPs are preserved independently.

### Human-Readable Formatting Output Example
```text
🚨 SECURITY ALERT
Type: Possible TCP SYN Port Scan
Source IP: 192.168.1.50
Destination IP: 192.168.1.10
Ports Scanned: [22, 23, 80, 443, 8080]
Time Window: 10 seconds
```

### Integration with `test_capture.py`
- Instantiated `alert_manager = AlertManager()` at module level.
- Updated `packet_callback(packet)` loop:
  ```python
  alerts = detection_engine.analyze(parsed_packet)
  for alert in alerts:
      processed_alert = alert_manager.process(alert)
      if processed_alert:
          print(alert_manager.format_alert(processed_alert))
  ```

### Files Changed
- `alert_manager.py`
- `test_alert_manager.py`
- `test_capture.py`
- `DEVELOPMENT_NOTES.md`

### Testing Performed & Exact Results
1. **Compilation Check**:
   ```bash
   .venv/bin/python -m py_compile alert_manager.py test_capture.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **AlertManager Unit Tests**:
   ```bash
   .venv/bin/python -m unittest test_alert_manager.py
   ```
   **Result**: 7/7 unit test cases passed in 0.000s (`OK`).
   - `test_no_alert`: `process(None)` returns `None`.
   - `test_single_alert`: stores single alert in history.
   - `test_multiple_alerts`: stores multiple unique alerts in history.
   - `test_duplicate_alert`: deduplicates identical type + source IP alert.
   - `test_different_alerts_are_not_deduplicated`: preserves different alert types from same IP.
   - `test_format_syn_flood_alert`: validates SYN flood format string.
   - `test_format_syn_scan_alert`: validates SYN scan format string.

3. **Regression & Integration Test Suites**:
   - `test_packet_parser.py`: 6/6 tests passed (`OK`).
   - `test_detection_engine.py`: 5/5 SYN scan scenarios passed.
   - `test_syn_flood_detector.py`: 5/5 SYN flood scenarios passed.
   - `test_detection_engine_unified.py`: both SYN scan and SYN flood alerts triggered via `DetectionEngine`.
   - `test_live_detection.py`: 5 SYN packets passed through `packet_callback()`, formatted SYN scan alert printed at 5th port.
   - `test_syn_flood_integration.py`: 20 SYN packets passed through `packet_callback()`, formatted SYN flood alert printed at 20th packet.

### Result
Status: SUCCESS

### Limitations & Next Planned Phase
- Deduplication currently relies on an in-memory alert list matching alert type + source IP without a time-decay reset mechanism.
- Integration tests used synthetic Scapy packets passed through `packet_callback()`, NOT real network attacks.
- **Next Phase**: **Phase 9 — Persistent Alert Logging & Storage**.

### Git Commit
Commit: 9c2dadb9ca367fdf17a8db3e301090e60d0e6893
Message: feat: add alert management
















