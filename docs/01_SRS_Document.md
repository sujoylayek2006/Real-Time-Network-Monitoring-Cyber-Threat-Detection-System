# Software Requirements Specification (SRS)
## Real-Time Network Monitoring and Threat Detection System
*(Web-Based Network Monitoring and Network Attack Analyzer)*

---

### Document Control
- **Project Title**: Real-Time Network Monitoring and Threat Detection System
- **Document Version**: 1.0.0
- **Standard**: IEEE Std 830-1998 Format
- **System Nature**: Pure Software Solution (No dedicated hardware appliances required; runs on standard OS network interfaces)
- **Target Audience**: College Project Evaluators, System Architects, Software Developers, Network Administrators

---

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) document details the functional, non-functional, interface, and operational requirements for the **Real-Time Network Monitoring and Threat Detection System**. The software is designed as a lightweight, full-stack, purely software-based network monitoring and threat analysis suite. It captures live network traffic via standard operating system software network adapters (NICs), decodes protocol headers, aggregates bandwidth and host metrics, detects malicious network activities (e.g., port scans, DoS attacks, ARP spoofing, brute-force connection attempts), and renders live telemetry on an interactive web dashboard.

### 1.2 Scope of the Software
The system delivers an end-to-end software platform comprising:
1. **Software Packet Sniffing & Capture Engine**: Promiscuous/raw socket listening over standard Ethernet/Wi-Fi software interfaces using `libpcap`/`scapy` drivers.
2. **Real-Time Protocol Dissector**: Layer 2 (Ethernet/ARP), Layer 3 (IPv4/IPv6, ICMP), Layer 4 (TCP, UDP), and Layer 7 (HTTP, DNS) header inspection and payload size extraction.
3. **Statistical & Rule-Based Threat Detection Engine**: Heuristic analysis for Port Scanning (SYN, FIN, XMAS, NULL, UDP scans), Volumetric DoS / DDoS (SYN flood, ICMP flood, UDP flood), ARP Cache Poisoning, and Repeated Authentication Brute Force.
4. **Bandwidth & Host Discovery Monitor**: Dynamic tracking of active IP/MAC endpoints, real-time download/upload throughput calculation, and protocol distribution breakdown.
5. **Real-Time Web Dashboard**: Responsive single-page application (SPA) displaying live streaming packet tables, dynamic line/bar charts, security alert feeds, and historical forensics.
6. **Alerting & Incident Store**: High-priority alert generation with severity tagging, persistent storage in MongoDB, and administrative log filtering.

### 1.3 Definitions, Acronyms, and Abbreviations
| Term / Acronym | Definition |
| :--- | :--- |
| **SRS** | Software Requirements Specification |
| **NIC** | Network Interface Card (Software Virtual or Physical Network Adapter) |
| **PCAP** | Packet Capture library / file format (`libpcap` / `Npcap`) |
| **Promiscuous Mode** | A network adapter software mode that passes all traffic received to the CPU, not just frames addressed to it |
| **DoS / DDoS** | Denial of Service / Distributed Denial of Service |
| **ARP** | Address Resolution Protocol |
| **SYN Flood** | A form of DoS attack in which an attacker sends successive SYN requests with no ACK completion |
| **Port Scan** | An automated scan across port ranges to discover open listening services and vulnerabilities |
| **SPA** | Single Page Application |
| **TTL** | Time To Live (Network packet hop limit or Database document expiration time) |
| **BSON** | Binary JavaScript Object Notation (MongoDB primary storage format) |
| **WebSocket** | Full-duplex persistent communication protocol over a single TCP connection |

### 1.4 References
- IEEE Std 830-1998: *IEEE Recommended Practice for Software Requirements Specifications*.
- RFC 791: *Internet Protocol (IP) Specification*.
- RFC 793: *Transmission Control Protocol (TCP) Specification*.
- RFC 768: *User Datagram Protocol (UDP) Specification*.
- RFC 826: *Ethernet Address Resolution Protocol (ARP)*.
- OWASP Top 10 Web Application Security Vulnerabilities (2021).

### 1.5 Overview of the Document
The remainder of this document outlines the high-level product characteristics, user personas, operating constraints, detailed functional specifications for each software module, data model requirements, performance benchmarks, and software-only system environment prerequisites.

---

## 2. Overall Description

### 2.1 Product Perspective
The system is an autonomous, standalone web application that sits atop the operating system's software networking stack. It operates out-of-band by passively capturing packets mirrored or routed through the host machine's software network interface without obstructing or introducing latency to active network traffic.

```
       [ Local Network Traffic / Gateway ]
                       │
                       ▼
       ┌───────────────────────────────┐
       │   Host Software NIC Adapter   │
       │     (Promiscuous/Raw Pcap)    │
       └───────────────┬───────────────┘
                       │ (Passive Packet Stream)
                       ▼
┌─────────────────────────────────────────────┐
│  Real-Time Network Monitoring & Threat Core │
│                                             │
│  ┌─────────────────┐   ┌──────────────────┐ │
│  │ Packet Sniffer  │──▶│ Protocol Parser  │ │
│  └─────────────────┘   └────────┬─────────┘ │
│                                 ▼           │
│  ┌─────────────────┐   ┌──────────────────┐ │
│  │ Alert Dispatch  │◀──│ Threat Detector  │ │
│  └────────┬────────┘   └────────┬─────────┘ │
│           │                     │           │
│           ▼                     ▼           │
│   [ WebSocket Gate ]    [ MongoDB Storage ] │
└───────────┼─────────────────────┼───────────┘
            │                     │
            ▼                     ▼
┌─────────────────────────────────────────────┐
│       Interactive Web Dashboard UI          │
│   (Live Charts, Alert Feed, Device Grid)    │
└─────────────────────────────────────────────┘
```

### 2.2 Product Functions
1. **Passive Packet Sniffing**: Continuous non-blocking packet ingestion from designated software network interfaces.
2. **Deep Packet Header Parsing**: Decoding Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, and HTTP headers to extract metadata (source IP, destination IP, ports, flags, payload lengths, timestamps).
3. **Live Bandwidth & Throughput Calculation**: Real-time aggregation of bytes per second (Bps), packets per second (pps), and protocol percentage splits.
4. **Host & Device Inventory**: Automatic discovery and status tracking of active network hosts mapped by IP and MAC addresses.
5. **Multi-Vector Attack Detection**:
   - *TCP SYN / FIN / NULL / XMAS Port Scans*
   - *UDP Port Sweeps*
   - *TCP SYN Flood / ICMP Ping Flood DoS*
   - *Gratuitous ARP Cache Poisoning / Spoofing*
   - *Repeated Connection & Brute Force Anomaly Detection*
6. **Real-Time Notification & Alert Dispatcher**: Sub-second push alerts over WebSockets directly to the web client.
7. **Forensic Log Querying & Filtering**: Searchable database of captured packets, detected security incidents, and traffic history with multi-parameter filtering.
8. **Administrative Control**: User authentication, threshold tuning (e.g., scan packet count thresholds, flood limits), and interface selection.

### 2.3 User Classes and Characteristics
| User Class | Description | Technical Expertise | System Privileges |
| :--- | :--- | :--- | :--- |
| **System Administrator** | Network engineer or system admin managing security. | High (Networking & Security) | Full access: configure thresholds, manage users, clear logs, select network adapters, export reports. |
| **Security Analyst / Auditor** | Junior admin or security reviewer inspecting logs and incident timelines. | Moderate to High | Read access to live metrics, forensic logs, alert details; can acknowledge/resolve alerts. |
| **General Viewer / Student** | Academic observer or lab supervisor reviewing network behavior. | Basic to Moderate | Read-only access to live dashboard, charts, and public threat statistics. |

### 2.4 Operating Environment
- **Operating System**: Cross-platform support for Windows 10/11, Linux (Ubuntu 20.04/22.04 LTS, Debian, Kali Linux), or macOS.
- **Runtime Environment**:
  - Backend: Python 3.10+ / Node.js 18+ LTS
  - Database: MongoDB 6.0+ Community / Enterprise Edition
  - Frontend: Modern Web Browsers (Chrome 100+, Firefox 95+, Edge 100+, Safari 15+)
- **Software Dependencies**: Npcap (Windows) or `libpcap` (Linux/macOS) driver layer.

### 2.5 Design and Implementation Constraints
1. **Software-Only Constraint**: The entire project must execute on commodity PC/laptop software environments without requiring specialized hardware firewalls, physical taps, or microcontrollers.
2. **Privilege Requirements**: Packet sniffing requires administrative/root or `CAP_NET_RAW` / `CAP_NET_ADMIN` software capabilities on the host OS.
3. **Performance Constraint**: Packet capture and parsing must run in asynchronous or multi-threaded background workers to prevent blocking the web server event loop.
4. **Browser Compatibility**: Zero client-side plugins; UI must rely entirely on standard HTML5, CSS3, ES6 JavaScript, and WebSockets.

### 2.6 Assumptions and Dependencies
- The host OS has a functioning physical or virtual network interface adapter (Ethernet, Wi-Fi, or Virtual Switch).
- For promiscuous packet capture on Windows, `Npcap` must be installed in WinPcap-compatible mode.
- MongoDB service is accessible locally or via a network connection string.

---

## 3. Specific Functional Requirements

### 3.1 Module 1: Packet Capture & Ingestion Engine
- **FR-1.1**: The system **SHALL** enumerate all available software network interface adapters (e.g., `eth0`, `wlan0`, `Ethernet`, `Wi-Fi`) and allow the administrator to select the target interface.
- **FR-1.2**: The system **SHALL** initiate packet capture in promiscuous mode to capture both unicast, multicast, and broadcast frames across the local subnet.
- **FR-1.3**: The capture engine **SHALL** operate asynchronously using non-blocking ring buffers or worker queues to sustain packet bursts of up to 15,000 packets per second without frame drops.
- **FR-1.4**: The system **SHALL** allow administrators to define BPF (Berkeley Packet Filter) expressions (e.g., `tcp or udp`, `not port 22`) to filter traffic at the software capture layer.

### 3.2 Module 2: Protocol Dissection & Header Parsing
- **FR-2.1**: The system **SHALL** decode Layer 2 Ethernet frames and extract source MAC, destination MAC, and EtherType.
- **FR-2.2**: The system **SHALL** decode ARP frames, identifying `ARP Request` (opcode 1) and `ARP Reply` (opcode 2) fields, sender IP/MAC, and target IP/MAC.
- **FR-2.3**: The system **SHALL** parse Layer 3 IPv4 and IPv6 headers, extracting Source IP, Destination IP, Protocol type (TCP, UDP, ICMP), TTL, and Total Length.
- **FR-2.4**: The system **SHALL** decode Layer 4 TCP headers, extracting Source Port, Destination Port, Sequence Number, Acknowledgment Number, and Control Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **FR-2.5**: The system **SHALL** decode Layer 4 UDP headers, extracting Source Port, Destination Port, and Datagram Length.
- **FR-2.6**: The system **SHALL** inspect ICMP headers, extracting Type (Echo Request, Echo Reply, Destination Unreachable) and Code.

### 3.3 Module 3: Bandwidth Aggregation & Device Inventory
- **FR-3.1**: The system **SHALL** compute rolling bandwidth statistics at 1-second intervals, calculating total bytes received, bytes sent, packets/sec, and Mbps throughput.
- **FR-3.2**: The system **SHALL** maintain a live in-memory registry of active devices on the subnet, indexed by MAC and IP addresses.
- **FR-3.3**: The system **SHALL** track per-device metrics: total bytes uploaded, total bytes downloaded, active protocols, and timestamp of first/last packet seen.
- **FR-3.4**: The system **SHALL** categorize traffic distribution by protocol percentages (TCP vs UDP vs ICMP vs ARP vs Other) for visual chart rendering.

### 3.4 Module 4: Security Threat & Attack Detection Engine
- **FR-4.1 (Port Scan Detection)**: The engine **SHALL** maintain a sliding time window (configurable, default 5 seconds) per source IP. If the distinct destination port count probed by a single source IP exceeds the threshold (default: > 20 distinct ports), a `PORT_SCAN_DETECTED` alert **SHALL** be triggered.
- **FR-4.2 (Stealth Scan Detection)**: The engine **SHALL** flag anomalous TCP flag combinations:
  - *NULL Scan*: No flags set (`0x00`).
  - *XMAS Scan*: `FIN`, `PSH`, and `URG` flags set simultaneously.
  - *FIN Scan*: Only `FIN` flag set without prior session handshake.
- **FR-4.3 (SYN Flood DoS Detection)**: The engine **SHALL** track unanswered TCP `SYN` packets per source IP. If the ratio of `SYN` requests to completing `ACK` packets exceeds 10:1 or the rate exceeds 100 SYN packets/sec from a source, a `SYN_FLOOD_DOS` alert **SHALL** be raised.
- **FR-4.4 (ICMP Ping Flood Detection)**: The engine **SHALL** flag ICMP Echo Requests exceeding a rate threshold (default: > 50 packets/sec per source IP) as an `ICMP_FLOOD_DOS` event.
- **FR-4.5 (ARP Spoofing / Poisoning Detection)**: The engine **SHALL** inspect incoming ARP replies. If an ARP reply maps an existing known IP to a differing MAC address, or issues unsolicited gratuitous ARP replies at high frequency, an `ARP_SPOOFING_ATTACK` alert **SHALL** be generated.
- **FR-4.6 (Brute-Force Connection Anomaly)**: The engine **SHALL** monitor rapid connection resets (`RST`) or repeated short-lived TCP connection attempts to sensitive authentication ports (Port 22 SSH, Port 21 FTP, Port 3389 RDP, Port 80/443 auth endpoints). If failed connection attempts exceed 15 attempts/minute, a `BRUTE_FORCE_SUSPECTED` alert **SHALL** be raised.

### 3.5 Module 5: Real-Time WebSocket Streaming & Alert Dispatcher
- **FR-5.1**: The system **SHALL** maintain full-duplex WebSocket connections with authenticated web dashboard clients.
- **FR-5.2**: The system **SHALL** broadcast live packet stream updates (throttled at 100ms batches) to connected dashboard clients.
- **FR-5.3**: The system **SHALL** immediately push high-priority security alerts with payload metadata, timestamp, severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and suggested mitigation steps.

### 3.6 Module 6: Historical Forensics & Log Persistence
- **FR-6.1**: The system **SHALL** persist all detected security incidents into the MongoDB `attack_logs` and `alerts` collections with full packet headers and forensic summaries.
- **FR-6.2**: The system **SHALL** support indexed searching and filtering of security logs by Date Range, Source IP, Destination IP, Threat Category, and Severity.
- **FR-6.3**: The system **SHALL** support automated data pruning via MongoDB TTL indexes for raw packet traces (configurable retention: e.g., 24 hours to 7 days) while preserving critical security incident logs indefinitely.

### 3.7 Module 7: Interactive Web Dashboard (User Interface)
- **FR-7.1**: The dashboard **SHALL** render a live system health banner showing packet capture state (Active/Paused), current NIC, throughput (KB/s, MB/s), and active threat counter.
- **FR-7.2**: The dashboard **SHALL** render real-time dynamic charts:
  - *Bandwidth Usage Over Time* (Ingress vs Egress live time-series chart)
  - *Protocol Breakdown* (Pie/Doughnut chart of TCP/UDP/ICMP/ARP)
  - *Top Talkers* (Bar chart of top 5 bandwidth-consuming IP addresses)
  - *Threat Distribution* (Radar or Bar chart of attack categories)
- **FR-7.3**: The dashboard **SHALL** render an interactive live packet stream table with sortable columns, protocol color-coding, and modal packet inspector.
- **FR-7.4**: The dashboard **SHALL** provide an Alert Center with visual badges, audio alert toggle, and one-click alert resolution status updates.

### 3.8 Module 8: System Configuration & Security
- **FR-8.1**: The system **SHALL** require administrator authentication using JSON Web Tokens (JWT) with salted password hashing (bcrypt).
- **FR-8.2**: The system **SHALL** provide a settings page to adjust detection thresholds, sampling rates, and notification sounds without requiring a server restart.

---

## 4. Non-Functional Requirements (NFRs)

### 4.1 Performance Requirements
- **NFR-1 (Latency)**: Web dashboard telemetry must update within 500ms of packet arrival on the network adapter.
- **NFR-2 (Throughput)**: The packet ingestion pipeline must parse at least 10,000 packets per second on standard dual-core consumer hardware without memory leaks or packet drop exceeding 0.1%.
- **NFR-3 (CPU & Memory Footprint)**: Total software memory utilization under steady state must not exceed 512 MB for the backend service and 150 MB for the browser client.

### 4.2 Scalability & Reliability
- **NFR-4 (Continuous Operation)**: The capture engine must run continuously 24/7 without crashing, automatically recovering if the network adapter undergoes a temporary link-down state.
- **NFR-5 (Graceful Degradation)**: Under heavy network flooding (> 50,000 pps), the system must prioritize threat detection evaluation and aggregated metrics over raw packet log persistence to safeguard database responsiveness.

### 4.3 Security Requirements
- **NFR-6 (Web Security)**: All REST API routes must be protected against Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and NoSQL Injection.
- **NFR-7 (Data Confidentiality)**: Passwords must be hashed using `bcrypt` with a minimum cost factor of 10. Sensitive authentication tokens must be transmitted over HTTPS/WSS in production environments.
- **NFR-8 (Sanitization)**: Raw packet payload strings displayed in the web UI must be properly HTML-escaped to prevent DOM-based XSS attacks through malicious network packet payloads.

### 4.4 Usability & Accessibility
- **NFR-9 (User Interface)**: The dashboard must feature a sleek, modern dark-themed interface with high contrast for security operations, clear typography, and responsive grid layouts supporting 1080p and 1440p displays.
- **NFR-10 (Error Feedback)**: Clear, human-readable error messages must be shown if packet capture fails due to insufficient OS privileges or unselected interfaces.

### 4.5 Maintainability & Extensibility
- **NFR-11 (Modular Architecture)**: Detection heuristics must be implemented as pluggable rule classes, allowing developers to introduce new signature or anomaly rules by adding a single module file.

---

## 5. External Interface Requirements

### 5.1 User Interfaces
- Modern Web Interface (HTML5, CSS3, React / Vanilla JS with Tailwind / Glassmorphism theme).
- Standard UI Components: Navigation Sidebar, Real-time Stat Cards, Chart Viewports, Live Data Tables, Modal Detail Inspector, Alert Notification Toaster.

### 5.2 Hardware Interface (Software Level)
- Standard Operating System Network Stack: Ethernet 802.3, Wi-Fi 802.11, or Virtual Local Area Network (VLAN) adapters exposed through the OS kernel driver layer.
- **Note**: Strictly standard PC software networking; no proprietary FPGA, microcontrollers, or external hardware appliances.

### 5.3 Software Interfaces
- **OS Packet Drivers**: `libpcap` (Linux/macOS) / `Npcap` / `WinPcap` (Windows).
- **Database**: MongoDB Driver over standard MongoDB wire protocol (Port 27017).
- **Web Protocols**: HTTP/1.1 or HTTP/2 for REST endpoints; RFC 6455 WebSocket for real-time bi-directional streaming.

---

## 6. System Verification Matrix

| Requirement ID | Description | Verification Method | Success Criteria |
| :--- | :--- | :--- | :--- |
| **FR-1.1 - 1.4** | Software NIC Packet Capture | Demonstration / Integration Test | Captures live packets from selected NIC adapter with 0 dropped frames. |
| **FR-2.1 - 2.6** | Protocol Dissection | Unit Test | Accurately extracts IP, MAC, TCP/UDP ports, and flags from test PCAPs. |
| **FR-4.1** | Port Scan Detection | Security Attack Simulation (`nmap`) | Triggers `PORT_SCAN_DETECTED` alert within 1 second of scan initiation. |
| **FR-4.3** | SYN Flood DoS Detection | Stress Test (`hping3` / Python script) | Triggers `SYN_FLOOD_DOS` alert when SYN rate exceeds threshold. |
| **FR-4.5** | ARP Spoofing Detection | Attack Simulation (`arpspoof` script) | Detects conflicting IP-MAC pair within 500ms. |
| **FR-5.1 - 5.3** | Live WebSocket Updates | End-to-End Test | Dashboard updates live charts and packet rows in under 500ms. |
| **FR-6.1 - 6.3** | Incident Persistence | Database Integration Test | Incident records persist in MongoDB and are queryable with compound filters. |
| **NFR-1 - NFR-3** | Latency and Resource Usage | Benchmark Load Test | Latency < 500ms; RAM footprint < 512MB under 10k packets/sec load. |
