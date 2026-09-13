# Comprehensive Testing & Quality Assurance Documentation
## Real-Time Network Monitoring and Threat Detection System

---

### Executive Summary
This document defines the comprehensive Quality Assurance (QA) and verification strategy for the **Real-Time Network Monitoring and Threat Detection System**. Given the real-time nature of packet inspection and security threat detection, the test plan encompasses unit testing, component integration, simulated cyber attack validation, stress/load benchmarking, and end-to-end UI verification.

---

## 1. Testing Strategy & Framework

```
               ┌────────────────────────────────────────┐
               │        End-to-End System Tests         │
               │   (UI Dashboard, WebSockets, Alerts)   │
               └───────────────────▲────────────────────┘
                                   │
               ┌───────────────────┴────────────────────┐
               │    Security & Attack Simulation Tests  │
               │  (Nmap, Scapy Scripts, DoS Flooding)   │
               └───────────────────▲────────────────────┘
                                   │
               ┌───────────────────┴────────────────────┐
               │          Integration Tests             │
               │  (Capture Worker ⇄ Parser ⇄ DB ⇄ WS)   │
               └───────────────────▲────────────────────┘
                                   │
               ┌───────────────────┴────────────────────┐
               │             Unit Tests                 │
               │ (Protocol Dissectors, Heuristic Rules) │
               └────────────────────────────────────────┘
```

### 1.1 Test Environments
- **Unit & Integration Test Suite**: Pytest (Python backend) / Jest (Node/Frontend) executing against mock packet bytes and in-memory test databases.
- **Attack Simulation Testbed**: Localhost virtual loopback or local isolated LAN testbed executing non-destructive software attack simulation scripts.

---

## 2. Test Case Specification Matrix

### 2.1 Unit Test Cases (Protocol Parsing & Heuristic Rules)

| Test ID | Module | Objective | Input Data / Precondition | Expected Result | Pass Criteria |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-UT-01** | Protocol Parser | Verify IPv4 header extraction | Raw 20-byte IPv4 packet buffer | Correctly extracts Source IP, Dest IP, TTL (64), Protocol (TCP). | Exact field match |
| **TC-UT-02** | Protocol Parser | Verify TCP flags decoding | Raw TCP packet with flags `0x12` (`SYN+ACK`) | `tcp_flags.syn == true`, `tcp_flags.ack == true`, others false. | Boolean flag match |
| **TC-UT-03** | Port Scan Rule | Verify threshold trigger | Stream of 25 SYN packets to ports 1..25 in 2 seconds | Triggers `PORT_SCAN_DETECTED` alert with severity `HIGH`. | Alert object created |
| **TC-UT-04** | Stealth Scan Rule | Verify NULL scan detection | Raw TCP segment with flags `0x00` | Triggers `STEALTH_SCAN_NULL` alert with severity `MEDIUM`. | Alert object created |
| **TC-UT-05** | Stealth Scan Rule | Verify XMAS scan detection | Raw TCP segment with flags `0x29` (`FIN+PSH+URG`)| Triggers `STEALTH_SCAN_XMAS` alert with severity `MEDIUM`. | Alert object created |
| **TC-UT-06** | Bandwidth Aggregator| Verify Throughput Math | 1,000 packets of 1,500 bytes over 1.0s interval | Returns throughput = 12.0 Mbps, total packets = 1,000. | Calculated value ±0.01% |
| **TC-UT-07** | ARP Spoof Rule | Verify conflicting MAC detection | Legitimate IP `192.168.1.1` mapped to MAC A; Ingest ARP reply with MAC B | Triggers `ARP_SPOOFING_ATTACK` with severity `CRITICAL`. | Alert object created |

---

### 2.2 Integration Test Cases

| Test ID | Modules Under Test | Test Scenario | Expected Result |
| :--- | :--- | :--- | :--- |
| **TC-IT-01** | Sniffer ⇄ Parser | Feed 500 raw packets into Sniffer queue | Parser dequeues and converts all 500 frames into normalized objects without memory leaks. |
| **TC-IT-02** | Parser ⇄ Threat Engine | Stream mix of normal HTTP traffic and 1 port scan | Engine passes normal traffic silently and dispatches exactly 1 alert event. |
| **TC-IT-03** | Threat Engine ⇄ MongoDB | Threat detection triggers alert | Incident document is persisted in `alerts` and `attack_logs` collections with complete metadata. |
| **TC-IT-04** | API ⇄ WebSocket | Client connects to WebSocket `/` | Receives live `metrics:update` every 1000ms and `packet:stream` batches every 100ms. |

---

### 2.3 Security & Attack Simulation Test Cases

| Test ID | Target Attack Vector | Software Simulation Tool | Execution Command / Script | Expected Detection Result |
| :--- | :--- | :--- | :--- | :--- |
| **TC-SEC-01** | TCP SYN Port Scan | `Nmap` (Software Scanner) | `nmap -sS -p 1-100 127.0.0.1` | `PORT_SCAN_DETECTED` alert pushed to dashboard within < 1.0s. |
| **TC-SEC-02** | TCP NULL Scan | `Nmap` | `nmap -sN -p 1-50 127.0.0.1` | `STEALTH_SCAN_NULL` alert pushed with affected ports logged. |
| **TC-SEC-03** | TCP XMAS Scan | `Nmap` | `nmap -sX -p 1-50 127.0.0.1` | `STEALTH_SCAN_XMAS` alert pushed with flag details. |
| **TC-SEC-04** | TCP SYN Flood DoS | Python Scapy Attack Script | Synthetic generator sending 200 SYN/sec to port 80 | `SYN_FLOOD_DOS` critical alert triggered with rate details. |
| **TC-SEC-05** | ICMP Ping Flood | `hping3` or Scapy Script | `hping3 --icmp --fast 127.0.0.1` | `ICMP_FLOOD_DOS` high-priority alert triggered. |
| **TC-SEC-06** | ARP Cache Poisoning | Python Scapy ARP Generator | Emits conflicting ARP reply for Gateway IP | `ARP_SPOOFING_ATTACK` critical alert with attacker MAC. |
| **TC-SEC-07** | SSH Brute Force | Python Socket Script | 20 rapid TCP connections to port 22 in 10s | `BRUTE_FORCE_SUSPECTED` alert triggered on port 22. |

---

### 2.4 Performance & Load Benchmarks

| Test ID | Benchmark Parameter | Target Load | Acceptance Threshold |
| :--- | :--- | :--- | :--- |
| **TC-PERF-01** | Packet Ingestion Rate | 10,000 packets / sec continuous for 5 minutes | Packet drop rate < 0.1%; zero crash or buffer deadlock. |
| **TC-PERF-02** | Detection Latency | Ingest attack packet amidst 5,000 pps background traffic | Alert dispatched to WebSocket client in $\le 500\text{ ms}$. |
| **TC-PERF-03** | Memory Footprint | 2 hours continuous sniffing | RAM utilization remains stable under 512 MB (no leak). |
| **TC-PERF-04** | UI Rendering FPS | Live packet table receiving 100ms batched updates | Web browser UI maintains 60 FPS without frame stutter. |

---

## 3. Attack Simulation Scripts (Test Harness)

The project includes built-in software simulation scripts to demonstrate and evaluate threat detection capabilities during testing and college presentations.

### 3.1 Port Scan & Stealth Scan Simulation Script (`test_scans.py`)
```python
"""
Non-destructive test script to simulate port scans and stealth probes on localhost.
Requires: scapy
"""
import time
from scapy.all import IP, TCP, send

TARGET_IP = "127.0.0.1"

def simulate_syn_port_scan(start_port=20, end_port=50):
    print(f"[*] Simulating TCP SYN Port Scan on {TARGET_IP} (Ports {start_port}-{end_port})...")
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.05) # Fast scan
    print("[+] SYN Port Scan simulation complete.")

def simulate_xmas_scan(ports=[80, 443, 8080]):
    print(f"[*] Simulating TCP XMAS Scan (FIN+PSH+URG) on {TARGET_IP}...")
    for port in ports:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="FPU")
        send(pkt, verbose=0)
    print("[+] XMAS Scan simulation complete.")

def simulate_null_scan(ports=[21, 22, 25]):
    print(f"[*] Simulating TCP NULL Scan (No Flags) on {TARGET_IP}...")
    for port in ports:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="")
        send(pkt, verbose=0)
    print("[+] NULL Scan simulation complete.")

if __name__ == "__main__":
    simulate_syn_port_scan()
    time.sleep(1)
    simulate_xmas_scan()
    time.sleep(1)
    simulate_null_scan()
```

### 3.2 DoS SYN Flood Simulation Script (`test_syn_flood.py`)
```python
"""
Non-destructive localhost SYN Flood simulator for detection engine verification.
"""
import time
from scapy.all import IP, TCP, send

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080
PACKET_COUNT = 150

def simulate_syn_flood():
    print(f"[*] Simulating SYN Flood ({PACKET_COUNT} packets) to {TARGET_IP}:{TARGET_PORT}...")
    for i in range(PACKET_COUNT):
        pkt = IP(dst=TARGET_IP)/TCP(sport=10000 + i, dport=TARGET_PORT, flags="S", seq=i*100)
        send(pkt, verbose=0)
    print("[+] SYN Flood simulation burst complete.")

if __name__ == "__main__":
    simulate_syn_flood()
```

---

## 4. Test Execution & Reporting Procedure

1. **Prerequisites Verification**: Ensure MongoDB service is active and backend server is running in test mode.
2. **Execute Automated Unit Suite**:
   ```bash
   pytest tests/test_parser.py tests/test_heuristics.py -v
   ```
3. **Execute Attack Simulation Testbed**:
   ```bash
   python tests/simulations/test_scans.py
   python tests/simulations/test_syn_flood.py
   ```
4. **Inspect Results**: Verify generated alerts in MongoDB and confirm real-time toast popups on the Web Dashboard UI.
