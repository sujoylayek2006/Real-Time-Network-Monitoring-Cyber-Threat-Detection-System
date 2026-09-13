# 30-Day Development & Implementation Plan
## Real-Time Network Monitoring and Threat Detection System

---

### Plan Overview
This 30-day development plan outlines the complete day-by-day roadmap for developing, testing, integrating, and demonstrating the **Real-Time Network Monitoring and Threat Detection System**. Structured into six progressive agile phases, it provides clear daily milestones, technical tasks, deliverables, and verification checkpoints.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               30-DAY DEVELOPMENT ROADMAP                               │
├─────────────────┬──────────────────┬─────────────────┬─────────────────┬───────────────┤
│ Phase 1         │ Phase 2          │ Phase 3         │ Phase 4         │ Phase 5 & 6   │
│ (Days 1–5)      │ (Days 6–10)      │ (Days 11–17)    │ (Days 18–22)    │ (Days 23–30)  │
├─────────────────┼──────────────────┼─────────────────┼─────────────────┼───────────────┤
│ Setup, Sniffer  │ Protocol Parser  │ Threat Engine & │ API Gateway,    │ Web Dashboard,│
│ & Ingestion     │ & Metrics Engine │ Heuristic Rules │ Persistence & WS│ Attack Testing│
│ Pipeline        │                  │                 │ Integration     │ & Final Demo  │
└─────────────────┴──────────────────┴─────────────────┴─────────────────┴───────────────┘
```

---

## Phase 1: Environment Setup, Architecture & Packet Capture Engine (Days 1 – 5)

### Day 1: Project Initialization & Toolchain Setup
- **Tasks**:
  - Initialize project repository structure (`/backend`, `/frontend`, `/docs`, `/tests`).
  - Configure Python virtual environment (`venv`) and install core dependencies (`scapy`, `fastapi`, `uvicorn`, `pymongo`, `python-socketio`).
  - Configure Node.js / React build tooling for the frontend SPA.
  - Setup local MongoDB database instance.
- **Deliverable**: Initialized repository with runnable backend and frontend skeletons.

### Day 2: Network Adapter Interface Discovery
- **Tasks**:
  - Implement `InterfaceManager` module to query host OS network adapters.
  - Extract IP, MAC, MTU, and operational status for physical and virtual NICs.
  - Implement CLI / API interface to select active capture adapter.
- **Deliverable**: Working script returning all local software network interfaces.

### Day 3: Raw Packet Sniffer Implementation
- **Tasks**:
  - Implement non-blocking asynchronous `PacketSniffer` class using raw socket / Scapy capture.
  - Configure promiscuous mode capture on selected interface.
  - Implement Berkeley Packet Filter (BPF) string parser to filter IP/ARP traffic.
- **Deliverable**: Working background capture loop streaming raw packet byte objects.

### Day 4: High-Performance Ring Buffer & Concurrency Setup
- **Tasks**:
  - Implement thread-safe FIFO Queue (`queue.Queue`) between sniffer thread and consumer thread.
  - Add packet drop counter and queue capacity safety limits.
  - Implement graceful start, pause, and stop controls.
- **Deliverable**: Zero-loss packet queuing pipeline capable of buffering bursts of 10,000+ packets.

### Day 5: Phase 1 Review & Benchmarking
- **Tasks**:
  - Benchmark packet capture throughput against high-volume web browsing and downloads.
  - Verify zero memory leaks during a 30-minute continuous capture run.
- **Deliverable**: Phase 1 verification milestone report.

---

## Phase 2: Protocol Dissection & In-Memory Metrics Pipeline (Days 6 – 10)

### Day 6: Layer 2 & Layer 3 Protocol Dissection
- **Tasks**:
  - Implement Ethernet II and ARP header parsers (MACs, EtherType, Opcode, Target/Sender IP).
  - Implement IPv4 / IPv6 header parsers (Source IP, Dest IP, TTL, Length, Protocol ID).
  - Implement ICMP type/code parser.
- **Deliverable**: Normalized data objects for L2/L3 frames.

### Day 7: Layer 4 Protocol Dissection (TCP / UDP)
- **Tasks**:
  - Implement TCP segment parser (Source/Dest Port, Seq, Ack, Flags: SYN, ACK, FIN, RST, PSH, URG).
  - Implement UDP datagram parser (Source/Dest Port, Length).
  - Extract application-layer hints (HTTP host/method, DNS queries).
- **Deliverable**: Complete protocol normalization schema for all major traffic.

### Day 8: Real-Time Bandwidth & Throughput Aggregator
- **Tasks**:
  - Implement 1-second sliding accumulator calculating total bytes, packets, and Mbps throughput.
  - Implement protocol percentage calculator (TCP %, UDP %, ICMP %, ARP %).
  - Implement top talkers tracker (identifying top 5 bandwidth-consuming IP addresses).
- **Deliverable**: `BandwidthAggregator` class outputting rolling 1-second telemetry JSON payloads.

### Day 9: Passive Device Discovery & Host Registry
- **Tasks**:
  - Implement `DeviceManager` maintaining an in-memory hash map of seen MAC and IP endpoints.
  - Implement OUI vendor lookup for MAC addresses.
  - Track upload/download bytes and timestamps per device.
- **Deliverable**: Real-time device registry module tracking connected network hosts.

### Day 10: Phase 2 Unit Testing
- **Tasks**:
  - Write Pytest unit tests for protocol dissectors (`test_parser.py`).
  - Test parser against sample `.pcap` files with known packet structures.
- **Deliverable**: 100% passing unit tests for packet parsing and bandwidth calculations.

---

## Phase 3: Real-Time Threat Detection & Heuristic Rules Engine (Days 11 – 17)

### Day 11: Threat Engine Architecture & Sliding Windows
- **Tasks**:
  - Design pluggable `IRule` interface and `ThreatDetectionEngine` coordinator.
  - Implement per-IP rolling sliding window buffer (`collections.deque`) with automated time-based eviction.
- **Deliverable**: Extensible threat engine foundation with sliding window state management.

### Day 12: Port Scan Detection Heuristic
- **Tasks**:
  - Implement `PortScanRule` tracking distinct destination ports queried per source IP.
  - Add configurable threshold trigger ($\ge 20$ ports in 5 seconds).
  - Add stealth scan rules for TCP NULL (`0x00`) and TCP XMAS (`FIN+PSH+URG`) flag patterns.
- **Deliverable**: Operational port scan and stealth scan detection module.

### Day 13: Volumetric DoS / DDoS Flood Detection
- **Tasks**:
  - Implement `DoSFloodRule` tracking TCP SYN packet rates and SYN-to-ACK completion ratios.
  - Implement ICMP Ping flood detector (detecting high pps echo requests).
  - Implement UDP volume flood detector.
- **Deliverable**: Real-time DoS/DDoS volumetric flood detector.

### Day 14: ARP Spoofing & Cache Poisoning Detection
- **Tasks**:
  - Implement `ARPSpoofRule` tracking authoritative IP-to-MAC pairings.
  - Flag incoming ARP replies that contradict known IP-MAC bindings.
  - Detect high-frequency unsolicited gratuitous ARP announcements.
- **Deliverable**: Real-time ARP spoofing and Man-in-the-Middle attack detector.

### Day 15: Brute-Force Connection Anomaly Detection
- **Tasks**:
  - Implement `BruteForceRule` monitoring rapid connection attempts and TCP RST responses on ports 21, 22, 3389, 8080.
  - Generate alert if failed connection frequency exceeds 15 attempts/minute.
- **Deliverable**: Brute-force credential stuffing detection module.

### Day 16: Alert Formatter, Severity Scoring & Remediation Engine
- **Tasks**:
  - Implement incident alert generator attaching severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Add actionable remediation guidelines (e.g., firewall command snippets) to each alert.
  - Implement alert cooldown suppression to prevent alert flooding.
- **Deliverable**: Structured alert generation and suppression module.

### Day 17: Phase 3 Verification & Rule Benchmarking
- **Tasks**:
  - Execute automated rule verification tests (`test_heuristics.py`).
  - Benchmark threat engine latency under 5,000 packets/sec simulated load.
- **Deliverable**: Phase 3 milestone sign-off with verified threat detection rules.

---

## Phase 4: Database Persistence, REST API & WebSocket Gateway (Days 18 – 22)

### Day 18: MongoDB Database Integration & Schemas
- **Tasks**:
  - Implement Mongoose / Motor schemas for `devices`, `packet_logs`, `bandwidth_metrics`, `alerts`, `attack_logs`, and `system_settings`.
  - Configure MongoDB TTL indexes (24-hour expiration for raw packets, 30-day for metrics).
  - Implement compound indexes for high-speed querying.
- **Deliverable**: Fully configured and indexed MongoDB database tier.

### Day 19: RESTful API Development
- **Tasks**:
  - Implement FastAPI / Express REST routes for system status, interface selection, and capture controls.
  - Implement paginated endpoints for alerts, attack logs, and connected devices with search filters.
  - Implement endpoint for updating alert status (`ACKNOWLEDGED`, `RESOLVED`).
- **Deliverable**: Complete REST API verified with Postman / Swagger documentation.

### Day 20: Real-Time WebSocket Server Implementation
- **Tasks**:
  - Implement Socket.io / WebSocket server gateway.
  - Build throttled 100ms packet batch emitter (`packet:stream`).
  - Build 1-second bandwidth telemetry emitter (`metrics:update`).
  - Build instant high-priority alert broadcaster (`alert:new`).
- **Deliverable**: Bi-directional real-time WebSocket communication layer.

### Day 21: Authentication & Role-Based Access Control
- **Tasks**:
  - Implement user registration and login endpoints with `bcrypt` password hashing.
  - Implement JWT token generation and authentication middleware.
  - Secure sensitive administrative routes.
- **Deliverable**: Secure authentication subsystem with RBAC.

### Day 22: Phase 4 Integration Testing
- **Tasks**:
  - Run end-to-end integration tests connecting Capture Engine $\rightarrow$ Threat Engine $\rightarrow$ MongoDB $\rightarrow$ WebSockets.
  - Verify live data streaming to test WebSocket client.
- **Deliverable**: Phase 4 milestone sign-off with functioning backend pipeline.

---

## Phase 5: Modern Interactive Web Dashboard UI (Days 23 – 27)

### Day 23: Frontend Foundation & Design System Setup
- **Tasks**:
  - Setup React / Next.js SPA with Tailwind CSS and dark mode glassmorphism aesthetics.
  - Implement responsive dashboard layout (Sidebar, Header, Stat Cards, Live Status Banner).
  - Setup Socket.io client state synchronization.
- **Deliverable**: Responsive frontend shell connected to backend WebSocket feed.

### Day 24: Live Visual Charts & Telemetry Cards
- **Tasks**:
  - Implement real-time Bandwidth Line Chart (Ingress vs Egress Mbps) with smooth transitions.
  - Implement Protocol Breakdown Donut Chart (TCP, UDP, ICMP, ARP).
  - Implement Top Talkers Bar Chart and Summary Metric Badges.
- **Deliverable**: Dynamic live telemetry dashboard page.

### Day 25: Live Packet Stream Table & Inspector Modal
- **Tasks**:
  - Build virtualized live packet table with sortable columns (Time, Source, Dest, Protocol, Length).
  - Add protocol-specific color badges and pause/resume stream toggle.
  - Build modal inspector showing decoded packet headers and payload preview.
- **Deliverable**: Interactive packet analysis grid.

### Day 26: Threat Center & Real-Time Alert Hub
- **Tasks**:
  - Implement Alert Feed with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Add real-time audio chime toggle on new alert arrival.
  - Build alert action modal displaying attack forensics, packet samples, and one-click "Acknowledge" / "Resolve" buttons.
- **Deliverable**: Complete Security Alert Center UI.

### Day 27: Device Explorer, Forensic Log Query & Settings Panel
- **Tasks**:
  - Build Connected Devices grid showing vendor, IP, MAC, and bandwidth consumption.
  - Build Historical Log Query console with date pickers, protocol filters, and CSV export.
  - Build Settings panel for adjusting detection thresholds and capture interface.
- **Deliverable**: Fully completed web dashboard frontend.

---

## Phase 6: Attack Simulation Testing, Hardening & Project Polish (Days 28 – 30)

### Day 28: Simulated Cyber Attack Testing
- **Tasks**:
  - Execute attack simulation test suite (`test_scans.py`, `test_syn_flood.py`, `nmap` scans).
  - Validate real-time alert popups, database persistence, and visual chart spikes during simulated attacks.
  - Fine-tune detection thresholds to eliminate false positives.
- **Deliverable**: Verified attack detection test execution report with screenshots.

### Day 29: System Hardening & Performance Optimization
- **Tasks**:
  - Perform stress testing under sustained high packet rates (10,000 pps).
  - Optimize MongoDB queries and verify TTL auto-purge workers.
  - Audit UI responsiveness and frontend memory consumption.
- **Deliverable**: Production-ready, hardened codebase.

### Day 30: Final Demonstration Dry Run & Project Handover
- **Tasks**:
  - Complete full demonstration walk-through (Live sniffing $\rightarrow$ Launching attack $\rightarrow$ Dashboard alert pop $\rightarrow$ Forensic log export).
  - Finalize all project documentation, presentation slides, and user guide.
- **Deliverable**: Complete, verified project ready for college evaluation and submission.
