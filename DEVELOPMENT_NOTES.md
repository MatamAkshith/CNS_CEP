# Development Notes

## Project Overview

This project is a Computer Network Security (CNS) Coursework Enhancement Project (CEP) focused on developing a packet-sniffing and network-security analysis system using Python and Scapy. The system captures live network traffic, extracts and normalizes IP and transport layer packet headers, and provides a foundation for security analysis and anomaly detection.

---

### Current Architecture

```
                       main.py
             (Application Entry Point)
                         ↓
             Scapy Live Packet Capture
                         ↓
                  packet_callback()
                         ↓
                   packet_parser
                         ↓
              Normalized Packet Data
                         ↓
                  DetectionEngine
    ┌──────────┬──────────┬──────────┐
    ↓          ↓          ↓          ↓
SynScan    SynFlood    UdpScan    IcmpSweep
Detector   Detector    Detector   Detector
 (TCP)      (Flood)     (UDP)      (ICMP)
    └──────────┴──────────┴──────────┘
                         ↓
               List of Security Alerts
                         ↓
                    AlertManager
              ┌──────────┼──────────┐
              ↓          ↓          ↓
           History  Deduplication Formatting
              └──────────┬──────────┘
                         ↓
                Accepted Alert Stream
              ┌──────────┼──────────┐
              ↓          ↓          ↓
          Console    Statistics   StorageManager
          Output      Manager     (alerts.json)
                                      ↓
                                HTTP API Server
                               (http_server.py)
                              ┌───────┴───────┐
                              ↓               ↓
                        GET /alerts    GET /statistics
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
- ICMP protocol parsing (`protocol = "ICMP"`, `ip_version = 4`, Source IP `src`, Destination IP `dst`)
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
- Phase 8 — Alert Management Engine (`alert_manager.py` / `AlertManager` class supporting alert history, deduplication, and formatting)
- Phase 9 — Statistics & Analytics (`statistics_manager.py` / `StatisticsManager` class supporting metrics aggregation, top source, top alert type, and summary statistics)
- Phase 10 — Persistent Alert Logging (`storage_manager.py` / `StorageManager` class supporting persistent JSON alert logging in `alerts.json`)
- Phase 11 — HTTP Query Interface / API (`http_server.py` / RESTful endpoints `/alerts` and `/statistics`)
- Phase 12A — UDP Scan Detection (`udp_scan_detector.py` / `UdpScanDetector` detecting multi-port UDP recon)
- Phase 12B — ICMP Sweep Detection (`icmp_sweep_detector.py` / `IcmpSweepDetector` detecting ICMP host discovery)
- Phase 13.1 — Application Entry Point / Capture Pipeline (`main.py` standalone production application launcher)

### In Progress
- None (Phase 13.1 complete)

### Not Yet Implemented
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

---

## 2026-10-08 — Statistics & Analytics

### Objective
Implement `StatisticsManager` in `statistics_manager.py` to aggregate real-time threat metrics, count alerts by type and source IP, identify top offending source IPs and top alert types, and generate comprehensive analytical summaries.

### Architecture Role of StatisticsManager
`StatisticsManager` operates downstream of `AlertManager`. In the packet capture pipeline (`test_capture.py`), `StatisticsManager.process(processed_alert)` is invoked ONLY when `AlertManager.process(alert)` returns a non-None accepted alert:

```
DetectionEngine → raw alert list → AlertManager.process() → accepted alert → StatisticsManager.process() & Console Print
                                                        ↳ (rejected duplicate returns None, skipped by StatisticsManager)
```

### Relationship Between AlertManager and StatisticsManager
- **`AlertManager`**: Responsible for alert deduplication (matching alert type + source IP) and human-readable string formatting.
- **`StatisticsManager`**: Responsible for analytical aggregation. Because `StatisticsManager` receives only alerts accepted by `AlertManager`, duplicate alerts rejected by `AlertManager` are NOT counted in the statistical metrics, preventing skewed analytical totals.

### Methods Implemented
1. **`process(alert)`**: Stores non-None accepted alert dictionaries into internal list `self.alerts`. Ignores `None`.
2. **`get_total_alerts()`**: Returns integer count of total accepted alerts stored.
3. **`get_alerts_by_type()`**: Returns a dictionary mapping each alert type string to its occurrence count.
4. **`get_alerts_by_source()`**: Returns a dictionary mapping each source IP address to its alert count.
5. **`get_top_source()`**: Returns `{"source_ip": ip, "count": N}` for the source IP with the highest alert count, or `None` if no alerts exist.
6. **`get_top_alert_type()`**: Returns `{"type": alert_type, "count": N}` for the alert type with the highest count, or `None` if no alerts exist.
7. **`get_summary()`**: Returns a dictionary containing `total_alerts`, `alerts_by_type`, `alerts_by_source`, `top_source`, and `top_alert_type`.

### Files Added / Modified
- `statistics_manager.py` (New — `StatisticsManager` class implementation)
- `test_statistics_manager.py` (New — Unit test suite with 10 test cases)
- `test_statistics_integration.py` (New — Integration test suite with 3 test cases)
- `test_capture.py` (Updated — Instantiated `statistics_manager` and connected to accepted alert loop)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, status, and Change Log entry)

### Test Coverage & Exact Results
1. **Compilation Verification**:
   ```bash
   .venv/bin/python -m py_compile statistics_manager.py test_statistics_manager.py test_statistics_integration.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **AlertManager Unit Tests**:
   ```bash
   .venv/bin/python -m unittest test_alert_manager.py
   ```
   **Result**: 7/7 unit test cases passed in 0.000s (`OK`).

3. **Parser Unit Tests**:
   ```bash
   .venv/bin/python test_packet_parser.py
   ```
   **Result**: 6/6 tests passed in 0.001s (`OK`).

4. **SYN Scan Detector Unit Tests**:
   ```bash
   .venv/bin/python test_detection_engine.py
   ```
   **Result**: 5/5 SYN scan test scenarios passed.

5. **SYN Flood Detector Unit Tests**:
   ```bash
   .venv/bin/python test_syn_flood_detector.py
   ```
   **Result**: 5/5 SYN flood test scenarios passed.

6. **Unified Detection Engine Suite**:
   ```bash
   .venv/bin/python test_detection_engine_unified.py
   ```
   **Result**: Both SYN scan and SYN flood alerts triggered via `DetectionEngine`.

7. **StatisticsManager Unit Tests**:
   ```bash
   .venv/bin/python -m unittest test_statistics_manager.py
   ```
   **Result**: 10/10 unit test cases passed in 0.000s (`OK`) (`test_none_alert_is_ignored`, `test_single_alert`, `test_multiple_alerts`, `test_alerts_by_type`, `test_alerts_by_source`, `test_top_source`, `test_top_alert_type`, `test_top_source_with_no_alerts`, `test_top_alert_type_with_no_alerts`, `test_summary`).

8. **Statistics Integration Tests**:
   ```bash
   .venv/bin/python -m unittest test_statistics_integration.py
   ```
   **Result**: 3/3 integration test cases passed in 0.000s (`OK`) (`test_accepted_alert_is_counted`, `test_duplicate_alert_is_not_counted`, `test_different_alert_types_are_counted`).

9. **Live Detection Integration Tests**:
   - `test_live_detection.py`: Formatted TCP SYN port scan alert generated successfully.
   - `test_syn_flood_integration.py`: Formatted TCP SYN flood alert generated successfully.

### Result
Status: SUCCESS

### Limitations & Next Planned Phase
- **In-Memory Analytics Only**: `StatisticsManager` maintains analytics in RAM (`self.alerts = []`). It does NOT provide persistent database or file log storage. State resets upon process termination.
- **Synthetic Test Packets**: Integration tests (`test_live_detection.py`, `test_syn_flood_integration.py`) passed constructed Scapy packets directly through `packet_callback()`, NOT real malicious network attacks.
- **Detection Unchanged**: Detection logic, thresholds (`SynScanDetector`: 5 ports / 10s; `SynFloodDetector`: 20 SYNs / 5s), and parser implementations were left 100% unchanged.
- **Next Planned Phase**: **Phase 10 — Persistent Logging & Storage**.

---

## 2026-10-08 — Persistent Alert Logging

### Objective
Implement `StorageManager` in `storage_manager.py` to provide JSON-based persistent storage for accepted security alerts, saving alerts to `alerts.json` so security alerts survive process termination.

### Why JSON Persistence Was Selected
JSON file storage was selected over a relational or NoSQL database (e.g., SQLite, PostgreSQL, MongoDB) because:
1. **Zero External Dependencies**: Standard library `json` and `os` modules require no database server setup or driver installation.
2. **Direct Schema Match**: Alerts are generated and manipulated as native Python dictionary data structures, which serialize cleanly to JSON objects.
3. **Human-Readable & Inspection-Friendly**: Security administrators can open `alerts.json` in any text editor to audit detected threats.
4. **Scope-Appropriate**: Ideal for a coursework enhancement project (CEP) packet sniffer without adding heavy database daemon management overhead.

### Phase 10 Architecture & Workflow
`StorageManager` operates in parallel with `StatisticsManager` downstream of `AlertManager`:

```
Scapy sniff() → packet_callback() → parse_packet() → DetectionEngine
                                                          ↓
                                                     Raw Alerts
                                                          ↓
                                                 AlertManager.process()
                                                          ↓
                                                   Accepted Alert
                                            ┌─────────────┼─────────────┐
                                            ↓             ↓             ↓
                                      Console Output  Statistics   StorageManager
                                                       Manager     (alerts.json)
```

### StorageManager Responsibilities
- **`__init__(file_path="alerts.json")`**: Configures target storage file and triggers initialization.
- **`_initialize_storage()`**: Creates the storage file containing an empty JSON array (`[]`) if it does not already exist.
- **`load_alerts()`**: Reads and deserializes JSON content from `alerts.json`, returning a list of alert dictionaries.
- **`save_alerts(alerts)`**: Serializes and writes a complete list of alert dictionaries to `alerts.json` with 4-space indent formatting.
- **`save_alert(alert)`**: Appends a single newly accepted alert to existing stored alerts and persists the updated array to disk.

### `alerts.json` Structure
```json
[
    {
        "type": "Possible TCP SYN Port Scan",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "ports_scanned": [22, 23, 80, 443, 8080],
        "window": 10
    },
    {
        "type": "Possible TCP SYN Flood",
        "source_ip": "192.168.1.50",
        "syn_count": 20,
        "window": 5
    }
]
```

### AlertManager → StatisticsManager / StorageManager Flow
`AlertManager.process(alert)` acts as the gatekeeper:
- If an alert is a duplicate, `AlertManager` returns `None`. The live capture loop skips `None` alerts, so duplicates are neither passed to `StatisticsManager` nor written to `alerts.json` by `StorageManager`.
- If an alert is new/accepted, `AlertManager` returns the alert. The live capture loop passes it to `StatisticsManager.process(processed_alert)`, writes it via `storage_manager.save_alert(processed_alert)`, and prints the formatted string to the console.

### Files Created / Modified
- `storage_manager.py` (New — `StorageManager` class implementation)
- `test_storage_manager.py` (New — Unit test suite with 6 test cases)
- `test_storage_integration.py` (New — Integration test suite with 3 test cases)
- `test_storage_persistence.py` (New — Persistence verification test)
- `test_capture.py` (Updated — Instantiated `StorageManager` and integrated `save_alert` call)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, project status, and Phase 10 documentation entry)

### Test Coverage & Results
1. **Compilation Verification**:
   ```bash
   .venv/bin/python -m py_compile storage_manager.py test_capture.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **StorageManager Unit Tests (`test_storage_manager.py`)**:
   ```bash
   .venv/bin/python -m unittest test_storage_manager.py
   ```
   **Result**: 6/6 unit test cases passed in 0.002s (`OK`) (`test_storage_file_is_created`, `test_new_storage_is_empty`, `test_save_and_load_alerts`, `test_multiple_alerts`, `test_save_single_alert`, `test_save_multiple_alerts_individually`).

3. **Storage Integration Tests (`test_storage_integration.py`)**:
   ```bash
   .venv/bin/python -m unittest test_storage_integration.py
   ```
   **Result**: 3/3 integration test cases passed in 0.001s (`OK`) (`test_accepted_alert_is_stored`, `test_duplicate_alert_is_not_stored`, `test_different_alerts_are_stored`).

4. **Storage Persistence Verification (`test_storage_persistence.py`)**:
   ```bash
   .venv/bin/python -m unittest test_storage_persistence.py
   ```
   **Result**: 1/1 persistence test case passed in 0.001s (`OK`) (`test_alerts_survive_new_storage_manager`).

5. **Full System Regression**:
   - `test_alert_manager.py`: 7/7 passed
   - `test_packet_parser.py`: 6/6 passed
   - `test_detection_engine.py`: 5/5 passed
   - `test_syn_flood_detector.py`: 5/5 passed
   - `test_detection_engine_unified.py`: Passed (unified SYN scan & flood detection paths)
   - `test_statistics_manager.py`: 10/10 passed
   - `test_statistics_integration.py`: 3/3 passed
   - `test_live_detection.py`: Passed (TCP SYN port scan alert generated)
   - `test_syn_flood_integration.py`: Passed (TCP SYN flood alert generated)

### Persistence Verification Result
Verified that alerts written to disk by an initial `StorageManager` instance persist cleanly in `alerts.json` and are loaded intact by a separate, newly instantiated `StorageManager` object across process boundary simulation.

### Known Limitations
- **Course Project Scope**: JSON file storage is designed for lightweight coursework deployment. It is not intended for high-throughput production network monitoring.
- **No Concurrent Write Lock**: `StorageManager` performs full file reads/writes without file-locking mechanisms (`fcntl` or mutexes). Simultaneous writes from multiple processes could cause race conditions.
- **No Indexing / Query Optimization**: Filtering or searching stored alerts requires reading the entire JSON array into memory.

---

## 2026-10-08 — HTTP Query Interface / API

### Objective
Implement `http_server.py` to provide a lightweight RESTful HTTP query interface using Python standard library components (`http.server.HTTPServer` and `BaseHTTPRequestHandler`). This allows external HTTP clients, browser tools, and security dashboards to query persisted security alerts and analytics.

### Why Python Standard Library Was Selected
The HTTP server was built strictly using Python standard modules (`http.server`, `urllib.parse`, `json`) rather than external web frameworks (e.g. Flask, FastAPI, Django) because:
1. **Zero External Dependencies**: Standard library modules ensure the project runs out of the box in any standard Python environment without requiring additional `pip` installs.
2. **Lightweight & Fast**: Minimal overhead for course-project scope requirements.
3. **Transparent Execution**: Provides explicit control over request parsing, status code handling, header construction, and JSON response formatting.

### Phase 11 Architecture
`http_server.py` acts as an HTTP interface layer sitting on top of `StorageManager` and `StatisticsManager`:

```
   HTTP Client (curl / Browser / Dashboard)
                 │
                 ▼
       RequestHandler (BaseHTTPRequestHandler)
                 │
                 ├── GET /alerts?type=...&source_ip=... ──► StorageManager ──► alerts.json
                 │
                 └── GET /statistics ──────────────────► StatisticsManager ──► Analytical Summary
```

### Endpoint Documentation & Query Behavior
1. **`GET /alerts`**:
   - Fetches and returns all persisted security alerts from `alerts.json` as a JSON array.
   - **Supported Query Parameters**:
     - `type`: Filters alerts by matching alert type string (e.g. `/alerts?type=Possible%20TCP%20SYN%20Flood`).
     - `source_ip`: Filters alerts by matching source IP address (e.g. `/alerts?source_ip=192.168.1.50`).
     - **Combined Filtering**: Simultaneously filters by both `type` and `source_ip` (e.g. `/alerts?type=Possible%20TCP%20SYN%20Flood&source_ip=192.168.1.50`).
   - **Error Handling**: Passing unsupported query parameters (e.g. `/alerts?foo=bar`) returns HTTP `400 Bad Request` with an error message and a list of unsupported parameters.

2. **`GET /statistics`**:
   - Reads persisted alerts from `alerts.json`, processes them through a newly instantiated `StatisticsManager` instance, and returns an analytical summary JSON object containing:
     - `total_alerts`
     - `alerts_by_type`
     - `alerts_by_source`
     - `top_source`
     - `top_alert_type`
   - **Error Handling**: Query parameters are not allowed on `/statistics` (e.g. `/statistics?foo=bar`). Passing any query parameters returns HTTP `400 Bad Request`.

3. **`GET /<unknown>`**:
   - Returns HTTP `404 Not Found` with `{"error": "Endpoint not found"}`.

### Centralized `send_json_response()` Helper
The `RequestHandler` class encapsulates JSON response formatting in a dedicated method:
```python
def send_json_response(self, status_code, data):
    response = json.dumps(data).encode("utf-8")
    self.send_response(status_code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(response)))
    self.end_headers()
    self.wfile.write(response)
```

### HTTP Status & Error Codes
- **`200 OK`**: Successful request execution.
- **`400 Bad Request`**: Unsupported query parameters or query parameter usage on endpoints that forbid them.
- **`404 Not Found`**: Request to an undefined URL endpoint.
- **`500 Internal Server Error`**: Global try/except fallback handling unhandled server exceptions.

### Files Created / Modified
- `http_server.py` (New — `RequestHandler` and HTTP server runner)
- `test_http_server.py` (New — Automated HTTP API test suite)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, project status, and Phase 11 documentation entry)

### Test Coverage & Full System Regression
1. **Compilation Check**:
   ```bash
   .venv/bin/python -m py_compile http_server.py test_http_server.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **HTTP API Automated Test Suite (`test_http_server.py`)**:
   ```bash
   .venv/bin/python -m unittest test_http_server.py
   ```
   **Result**: 8/8 test cases passed in 0.516s (`OK`):
   - `test_get_all_alerts` (200 OK, returns all alerts)
   - `test_filter_by_type` (200 OK, filters by alert type)
   - `test_filter_by_source_ip` (200 OK, filters by source IP)
   - `test_combined_filter` (200 OK, filters by both type and source IP)
   - `test_statistics` (200 OK, computes analytical summary from storage)
   - `test_unknown_endpoint` (404 Not Found, error payload)
   - `test_unsupported_query_parameter` (400 Bad Request, list of invalid params)
   - `test_statistics_query_parameter` (400 Bad Request, query parameter forbidden)

3. **Full Regression Suite**:
   - `test_alert_manager.py`: 7/7 passed
   - `test_packet_parser.py`: 6/6 passed
   - `test_detection_engine.py`: 5/5 passed
   - `test_syn_flood_detector.py`: 5/5 passed
   - `test_detection_engine_unified.py`: Passed (unified detection engine paths)
   - `test_statistics_manager.py`: 10/10 passed
   - `test_statistics_integration.py`: 3/3 passed
   - `test_storage_manager.py`: 6/6 passed
   - `test_storage_integration.py`: 3/3 passed
   - `test_storage_persistence.py`: 1/1 passed
   - `test_live_detection.py`: Passed (live SYN scan simulation)
   - `test_syn_flood_integration.py`: Passed (live SYN flood simulation)

### Known Limitations
- **Read-Only API**: The HTTP API currently supports only `GET` requests; it does not accept `POST`, `PUT`, or `DELETE` methods.
- **No Authentication / Authorization**: The server provides public endpoint access without token/password header checks.
- **Single-Threaded Server**: Uses Python standard library `HTTPServer` designed for local course-project development, not heavy concurrent production loads.
- **No Pagination**: `/alerts` returns the complete list of persisted alerts without limit/offset pagination.
- **No Rate Limiting**: Does not limit client request rates.
- **Persistence Dependent**: Storage layer remains file-based JSON (`alerts.json`).

---

## 2026-10-08 — UDP Scan Detection (Phase 12A)

### Objective
Implement `UdpScanDetector` in `udp_scan_detector.py` and register it inside `DetectionEngine` (`detection_engine.py`) to detect multi-port UDP reconnaissance attacks across network traffic.

### Why UDP Scan Detection Was Added
Unlike TCP, UDP is a connectionless protocol that does not utilize a three-way handshake (SYN/SYN-ACK/ACK). Services such as DNS (port 53), DHCP (ports 67/68), NTP (port 123), SNMP (port 161), and IPsec (port 500) rely on UDP. Attackers send raw UDP datagrams to various ports to discover open services and map vulnerable network assets. Adding `UdpScanDetector` complements the existing TCP SYN scan and SYN flood detectors to provide multi-protocol security coverage.

### Detection Rule & Configuration
- **Protocol**: UDP (`packet.get("protocol") == "UDP"`)
- **Time Window**: 10 seconds (`time_window = 10`)
- **Port Threshold**: 5 unique destination ports (`port_threshold = 5`)
- **Scope**: Tracks unique target destination ports independently for each `(source_ip, destination_ip)` pair.

### Exact Implementation Details
1. **`UdpScanDetector` (`udp_scan_detector.py`)**:
   - `__init__(time_window=10, port_threshold=5)`: Initializes parameters and tracking dictionary `self.tracker`.
   - `analyze(packet)`:
     - Ignores non-UDP packets (`protocol != "UDP"` returns `None`).
     - Extracts `source_ip`, `destination_ip`, `destination_port`, and `timestamp`. Returns `None` if any field is missing.
     - Maps timestamps and destination ports under connection key tuple `(source_ip, destination_ip)`.
     - Evicts timestamps older than 10 seconds.
     - Calculates set of unique destination ports within the window.
     - Returns alert dictionary when unique port count reaches or exceeds 5:
       ```python
       {
           "type": "Possible UDP Port Scan",
           "source_ip": source_ip,
           "destination_ip": destination_ip,
           "ports_scanned": sorted(unique_ports),
           "window": 10
       }
       ```

2. **`DetectionEngine` (`detection_engine.py`)**:
   - Registered `UdpScanDetector()` inside `DetectionEngine.__init__()` array alongside `SynScanDetector()` and `SynFloodDetector()`.
   - `DetectionEngine.analyze(packet)` automatically routes normalized packets through all three security detectors.

### Files Added / Modified
- `udp_scan_detector.py` (New — `UdpScanDetector` class)
- `detection_engine.py` (Modified — Registered `UdpScanDetector` in `DetectionEngine`)
- `test_udp_scan_detector.py` (New — Unit test suite with 5 test cases)
- `test_detection_engine_udp.py` (New — `DetectionEngine` integration test for UDP scan)
- `test_udp_scan_integration.py` (New — End-to-end `packet_callback` integration test)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, project status, and Phase 12A documentation entry)

### Test Coverage & Verification Results

1. **Compilation Check**:
   ```bash
   .venv/bin/python -m py_compile udp_scan_detector.py detection_engine.py test_udp_scan_detector.py test_detection_engine_udp.py test_udp_scan_integration.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **UDP Scan Detector Unit Tests (`test_udp_scan_detector.py`)**:
   ```bash
   .venv/bin/python test_udp_scan_detector.py
   ```
   **Result**: 5/5 test cases passed (`OK`):
   - Test 1: 4 unique UDP ports -> no alert
   - Test 2: 5 unique UDP ports -> alert triggered (`Possible UDP Port Scan`)
   - Test 3: Duplicate ports -> no alert
   - Test 4: Packets outside 10s time window -> no alert
   - Test 5: Non-UDP packets (TCP) -> no alert

3. **DetectionEngine UDP Integration Test (`test_detection_engine_udp.py`)**:
   ```bash
   .venv/bin/python test_detection_engine_udp.py
   ```
   **Result**: Passed (`DetectionEngine` correctly returned `Possible UDP Port Scan` alert).

4. **End-to-End Callback Integration Test (`test_udp_scan_integration.py`)**:
   ```bash
   .venv/bin/python test_udp_scan_integration.py
   ```
   **Result**: Passed (Constructed Scapy `IP/UDP` packets to ports 53, 67, 123, 161, 500; successfully triggered alert through `packet_callback()` pipeline -> `parse_packet()` -> `DetectionEngine` -> `AlertManager` -> `StatisticsManager` -> `StorageManager` -> formatted alert output).

5. **Full System Regression Suite**:
   - `test_alert_manager.py`: 7/7 passed
   - `test_packet_parser.py`: 6/6 passed
   - `test_detection_engine.py`: 5/5 passed
   - `test_syn_flood_detector.py`: 5/5 passed
   - `test_detection_engine_unified.py`: Passed (unified SYN scan & flood detection paths)
   - `test_statistics_manager.py`: 10/10 passed
   - `test_statistics_integration.py`: 3/3 passed
   - `test_storage_manager.py`: 6/6 passed
   - `test_storage_integration.py`: 3/3 passed
   - `test_storage_persistence.py`: 1/1 passed
   - `test_http_server.py`: 8/8 passed
   - `test_live_detection.py`: Passed (live SYN scan simulation)
   - `test_syn_flood_integration.py`: Passed (live SYN flood simulation)

### Known Limitations
- **Passive Header Analysis Only**: Relies strictly on sent UDP packet headers; does not evaluate ICMP Port Unreachable response packets.
- **In-Memory Window State**: Tracking dictionaries are maintained in RAM and reset upon process termination.
- **Static Window Configuration**: Fixed 10-second window / 5-port threshold; low-and-slow scans spanning longer intervals will evade detection.

---

## 2026-10-08 — ICMP Sweep Detection (Phase 12B)

### Objective
Implement `IcmpSweepDetector` in `icmp_sweep_detector.py`, extend `packet_parser.py` to recognize ICMP protocol headers, update `alert_manager.py` to format ICMP alerts, and register `IcmpSweepDetector` inside `DetectionEngine` (`detection_engine.py`) to detect host discovery reconnaissance across IP subnets.

### Why ICMP Sweep Detection Was Added
Attackers use ICMP Echo Request ("ping sweep") messages as an initial host-discovery technique to map active IP addresses across a target network prior to executing port-specific reconnaissance (such as TCP SYN scans or UDP scans). Detecting ICMP host sweeps provides early-stage threat detection at Layer 3, complementing Layer 4 TCP SYN scan, TCP SYN flood, and UDP scan detection.

### Detection Rule & Configuration
- **Protocol**: ICMP (`packet.get("protocol") == "ICMP"`)
- **Time Window**: 10 seconds (`time_window = 10`)
- **Host Threshold**: 5 unique destination hosts (`host_threshold = 5`)
- **Scope**: Tracks unique destination IP addresses independently for each source IP address (`source_ip`).
- **Alert Type**: `"Possible ICMP Host Sweep"`

### Exact Implementation Details
1. **`IcmpSweepDetector` (`icmp_sweep_detector.py`)**:
   - `__init__(time_window=10, host_threshold=5)`: Initializes tracking dictionary `self.tracker`.
   - `analyze(packet)`:
     - Ignores non-ICMP packets (`protocol != "ICMP"` returns `None`).
     - Extracts `source_ip`, `destination_ip`, and `timestamp`. Returns `None` if any field is missing.
     - Maps timestamps and destination IPs under source IP key `source_ip`.
     - Evicts timestamp entries older than 10 seconds.
     - Calculates set of unique destination IP addresses.
     - Triggers structured alert dictionary when unique destination count reaches or exceeds 5:
       ```python
       {
           "type": "Possible ICMP Host Sweep",
           "source_ip": source_ip,
           "hosts_scanned": sorted(unique_destinations),
           "window": 10
       }
       ```

2. **Packet Parser Extension (`packet_parser.py`)**:
   - Added Scapy `ICMP` layer import (`from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP`).
   - Added `elif ICMP in packet: data["protocol"] = "ICMP"` branch.
   - Output normalized dictionary reports `protocol = "ICMP"` for ICMP IPv4 frames.
   - *Note*: ICMPv6 header parsing is not included in Phase 12B.

3. **DetectionEngine Integration (`detection_engine.py`)**:
   - Registered `IcmpSweepDetector()` in `DetectionEngine.__init__()` array alongside `SynScanDetector()`, `SynFloodDetector()`, and `UdpScanDetector()`.
   - `DetectionEngine.analyze(packet)` automatically routes normalized packets through all four security detectors.

4. **AlertManager Formatting (`alert_manager.py`)**:
   - Added support for `hosts_scanned` array formatting in `AlertManager.format_alert()`:
     ```python
     if "hosts_scanned" in alert:
         message += f"\nHosts Scanned: {alert.get('hosts_scanned')}"
     ```
   - Updated `test_alert_manager.py` with `test_format_icmp_sweep_alert()` (suite expanded to 8 test cases).

### Files Added / Modified
- `icmp_sweep_detector.py` (New — `IcmpSweepDetector` class)
- `test_icmp_sweep_detector.py` (New — Detector unit test suite with 5 test cases)
- `test_icmp_parser.py` (New — ICMP parser unit test)
- `test_detection_engine_icmp.py` (New — `DetectionEngine` ICMP sweep test)
- `test_icmp_sweep_integration.py` (New — End-to-end `packet_callback` integration test)
- `packet_parser.py` (Modified — Added ICMP protocol recognition)
- `detection_engine.py` (Modified — Registered `IcmpSweepDetector`)
- `alert_manager.py` (Modified — Added `hosts_scanned` formatting)
- `test_alert_manager.py` (Modified — Added ICMP alert format test)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, project status, and Phase 12B documentation)
- `alerts.json` (Modified — Updated persistent alert store from integration test execution)

### Test Coverage & Verification Results

1. **Compilation Check**:
   ```bash
   .venv/bin/python -m py_compile icmp_sweep_detector.py packet_parser.py detection_engine.py alert_manager.py test_icmp_sweep_detector.py test_icmp_parser.py test_detection_engine_icmp.py test_icmp_sweep_integration.py
   ```
   **Result**: Clean compilation, zero syntax errors.

2. **ICMP Sweep Detector Unit Tests (`test_icmp_sweep_detector.py`)**:
   ```bash
   .venv/bin/python test_icmp_sweep_detector.py
   ```
   **Result**: 5/5 test cases passed (`OK`):
   - Test 1: 4 unique destination hosts -> no alert
   - Test 2: 5 unique destination hosts -> alert triggered (`Possible ICMP Host Sweep`)
   - Test 3: Duplicate destination IPs -> no alert
   - Test 4: Packets outside 10s time window -> no alert
   - Test 5: Non-ICMP packets (TCP) -> no alert

3. **ICMP Parser Test (`test_icmp_parser.py`)**:
   ```bash
   .venv/bin/python test_icmp_parser.py
   ```
   **Result**: Passed (`protocol = "ICMP"` verified).

4. **DetectionEngine ICMP Integration Test (`test_detection_engine_icmp.py`)**:
   ```bash
   .venv/bin/python test_detection_engine_icmp.py
   ```
   **Result**: Passed (`DetectionEngine` returned `Possible ICMP Host Sweep` alert).

5. **End-to-End Callback Integration Test (`test_icmp_sweep_integration.py`)**:
   ```bash
   .venv/bin/python test_icmp_sweep_integration.py
   ```
   **Result**: Passed (Constructed Scapy `IP/ICMP` packets to 5 destination IPs; triggered alert through `packet_callback()` pipeline -> `parse_packet()` -> `DetectionEngine` -> `AlertManager` -> `StatisticsManager` -> `StorageManager` -> formatted alert output).

6. **AlertManager Unit Test Suite (`test_alert_manager.py`)**:
   ```bash
   .venv/bin/python -m unittest test_alert_manager.py
   ```
   **Result**: 8/8 unit test cases passed in 0.000s (`OK`).

7. **Full System Regression Suite**:
   - `test_packet_parser.py`: 6/6 passed
   - `test_detection_engine.py`: 5/5 passed
   - `test_syn_flood_detector.py`: 5/5 passed
   - `test_detection_engine_unified.py`: Passed (unified detection engine paths)
   - `test_udp_scan_detector.py`: 5/5 passed
   - `test_detection_engine_udp.py`: Passed
   - `test_udp_scan_integration.py`: Passed
   - `test_statistics_manager.py`: 10/10 passed
   - `test_statistics_integration.py`: 3/3 passed
   - `test_storage_manager.py`: 6/6 passed
   - `test_storage_integration.py`: 3/3 passed
   - `test_storage_persistence.py`: 1/1 passed
   - `test_http_server.py`: 8/8 passed
   - `test_live_detection.py`: Passed (live SYN scan simulation)
   - `test_syn_flood_integration.py`: Passed (live SYN flood simulation)

### Known Limitations
- **IPv4 ICMP Only**: Phase 12B implements IPv4 ICMP recognition; ICMPv6 (`IPv6` + `ICMPv6EchoRequest`) host sweeps are not currently handled.
- **Outbound Traffic Only**: Detection triggers based on observed ICMP traffic sent by a source IP; it does not analyze returning ICMP Echo Reply packets or confirm host availability.
- **In-Memory Tracking State**: Tracking state resets upon process termination.
- **Static Configuration**: Threshold set to 5 hosts / 10-second window.

---

## 2026-10-08 — Application Entry Point / Capture Pipeline (Phase 13.1)

### Objective
Introduce `main.py` as the official, standalone application entry point for the packet-sniffer system, establishing a clean separation between production application startup and test-oriented execution scripts (`test_capture.py`).

### Architecture & Capture Flow
The complete runtime capture pipeline is wired inside `main.py`:

```
main.py (Application Entry Point)
   ↓
initialize DetectionEngine
   ↓
initialize AlertManager
   ↓
initialize StatisticsManager
   ↓
initialize StorageManager
   ↓
Scapy sniff()
   ↓
packet_callback()
   ↓
parse_packet() (packet_parser)
   ↓
DetectionEngine (SynScan, SynFlood, UdpScan, IcmpSweep)
   ↓
AlertManager (Deduplication & Formatting)
   ↓
StatisticsManager + StorageManager (alerts.json)
```

### Exact Implementation
`main.py` encapsulates the complete end-to-end operational pipeline:
- **Imports**: Loads `DetectionEngine`, `AlertManager`, `StatisticsManager`, `StorageManager`, `parse_packet`, and Scapy `sniff`.
- **Initialization**: Instantiates global application managers: `detection_engine`, `alert_manager`, `statistics_manager`, and `storage_manager`.
- **`packet_callback(packet)`**:
  1. Parses raw captured packet via `parse_packet(packet)`.
  2. Passes normalized packet payload dictionary to `detection_engine.analyze(parsed_packet)`.
  3. Iterates over generated security alerts, processing each through `alert_manager.process(alert)`.
  4. For accepted (non-duplicate) alerts:
     - Updates real-time threat metrics in `statistics_manager.process(processed_alert)`.
     - Persists alert payload to `alerts.json` via `storage_manager.save_alert(processed_alert)`.
     - Renders formatted alert to console using `alert_manager.format_alert(processed_alert)`.
  5. Prints human-readable normalized packet details to terminal.
- **`main()`**: Prints startup banner, initiates `sniff(prn=packet_callback)`, and catches `KeyboardInterrupt` (`Ctrl+C`) for graceful shutdown.

### Application Entry Point
```python
if __name__ == "__main__":
    main()
```
`main.py` serves as the primary executable script for running the packet sniffer in production environments.

### Execution Command
```bash
sudo .venv/bin/python main.py
```
*Note*: On macOS, packet capture requires `sudo` privileges to open Berkeley Packet Filter (`/dev/bpf*`) network interfaces.

### Live Capture Verification
Live packet capture was verified using `main.py` on active network interfaces. The application captured and displayed real-time traffic including:
- IPv4 TCP traffic
- IPv6 TCP traffic
- IPv6 UDP traffic
- ARP broadcast frames
- General IPv4/IPv6 traffic

Interrupting the live capture via `Ctrl+C` stopped the process cleanly with `"Packet capture stopped cleanly."` without tracebacks or errors.

### Automated Regression Testing
Executed project-wide automated test suite:
```bash
.venv/bin/python -m unittest discover
```
**Result**:
```text
Ran 45 tests in 0.529s
OK
```
All **45/45** test cases passed cleanly.

### Regression Coverage
The automated test discovery suite verified the full spectrum of implemented features:
- TCP SYN Scan Detection (`SynScanDetector`)
- TCP SYN Flood Detection (`SynFloodDetector`)
- UDP Port Scan Detection (`UdpScanDetector`)
- ICMP Host Sweep Detection (`IcmpSweepDetector`)
- Packet Parser Protocol Normalization (`packet_parser.py`)
- Unified Detection Engine (`DetectionEngine`)
- Alert Manager Deduplication & Formatting (`AlertManager`)
- Statistics & Analytics Aggregation (`StatisticsManager`)
- Persistent JSON Alert Storage (`StorageManager` / `alerts.json`)
- RESTful HTTP Query API Server (`http_server.py`)

### Design Decisions
The implementation intentionally remained minimal and pragmatic:
- Reused all existing, fully-tested detection, parsing, alert, statistics, and storage modules without modification.
- Avoided adding heavy web frameworks, external database dependencies, or unnecessary abstraction layers.
- Maintained a clean separation between the production application entry point (`main.py`) and developer test scripts (`test_capture.py`).

### Files Created / Modified
- `main.py` (New — Standalone application entry point)
- `DEVELOPMENT_NOTES.md` (Updated — Architecture, project status, and Phase 13.1 documentation)

### Known Limitations
- **Privilege Requirement**: Scapy live capture requires `sudo` / root permissions on macOS for BPF interface access.
- **Default Interface**: Captures on Scapy's default network interface. Interface selection/CLI argument flags are not yet implemented.
- **Inline Wiring**: `main.py` contains `packet_callback` wiring inline rather than introducing a separate capture module abstraction.

### Project Status
- **Phase 13.1 — Application Entry Point / Capture Pipeline**: COMPLETE






















