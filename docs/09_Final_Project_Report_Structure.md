# Academic Final Project Report Structure & Guidelines
## Real-Time Network Monitoring and Threat Detection System
*(Web-Based Network Monitoring and Network Attack Analyzer)*

---

### Purpose of this Document
This document defines the formal, university-standard academic project thesis / dissertation structure for the **Real-Time Network Monitoring and Threat Detection System**. It complies with standard Engineering College and IEEE formatting guidelines, providing a chapter-by-chapter blueprint, subsection outlines, expected contents, diagrams, and citation formats.

---

## 1. Preliminary Pages (Standard Academic Formatting)

1. **Title Page**
   - Project Title: *Real-Time Network Monitoring and Threat Detection System*
   - Subtitle: *A Web-Based Network Monitoring and Network Attack Analyzer*
   - Student Name(s), Roll / Registration Number(s)
   - Degree (e.g., Bachelor of Technology in Computer Science & Engineering)
   - Department, College / Institute Name, University Name & Logo
   - Academic Year (e.g., 2026–2027)
2. **Certificate of Approval** (Signed by Project Supervisor / Guide, Head of Department, External Examiner)
3. **Student Declaration** (Originality declaration signed by candidates)
4. **Acknowledgements** (Gratitude to Guide, HOD, Faculty, Lab Technicians, Family)
5. **Abstract** (Executive summary of 250–350 words highlighting problem, methodology, software architecture, results, and conclusion)
6. **Table of Contents** (Structured chapter and section list with page numbers)
7. **List of Figures** (Captioned figure titles with corresponding page numbers)
8. **List of Tables** (Captioned table titles with corresponding page numbers)
9. **List of Abbreviations** (Acronym glossary: NIC, PCAP, TCP, UDP, ICMP, ARP, DoS, IDS, BPF, SPA, etc.)

---

## 2. Chapter-by-Chapter Detailed Blueprint

### Chapter 1: Introduction
- **1.1 Background & Motivation**: The rapid growth of enterprise and campus network infrastructures; increasing sophistication of cyber threats (port scanning, volumetric DoS, ARP cache poisoning); the necessity for lightweight, real-time, web-based visibility.
- **1.2 Problem Statement**: Existing network monitoring tools (such as Wireshark or standalone CLI sniffers) are either offline packet dump viewers lacking automated threat detection or enterprise appliances requiring expensive hardware and steep learning curves. There is a critical need for an integrated, software-only, real-time network monitoring and threat detection suite accessible via modern web browsers.
- **1.3 Project Objectives**:
  - Implement a passive software packet capture engine over standard OS network adapters.
  - Decode multi-layer protocol headers in real time.
  - Implement heuristic and rule-based algorithms to detect active port scans, DoS attacks, ARP spoofing, and brute-force attempts.
  - Deliver a dynamic, responsive web dashboard with live charts, telemetry badges, and instant WebSocket alerts.
  - Store security incident forensics in MongoDB with automated retention management.
- **1.4 Project Scope & Boundaries**: Pure software solution running on host OS software interfaces; covers Layer 2 to Layer 7 protocols on local and routed networks.
- **1.5 Organization of the Report**: Brief chapter-wise overview of the remaining document.

---

### Chapter 2: Literature Survey & Existing Systems
- **2.1 Review of Existing Network Monitoring Tools**:
  - *Wireshark / TShark*: In-depth packet analysis, but complex GUI, high resource consumption, and lacks native real-time automated web alert push.
  - *Snort / Suricata*: Powerful signature-based Intrusion Detection Systems (IDS), but complex configuration syntax and heavy resource overhead for small-to-medium networks.
  - *Zeek (Bro)*: Network security monitoring engine, geared toward deep enterprise scripting rather than lightweight out-of-the-box visual dashboards.
- **2.2 Comparative Analysis of Existing Systems vs Proposed System**:
  - Comparison table covering: Web Dashboard, Real-Time Alerts, Hardware Requirement (Hardware Tap vs Pure Software), Protocol Inspection, Resource Footprint, Ease of Deployment.
- **2.3 Identified Research Gaps**: Absence of an accessible, all-in-one web-based solution combining packet analysis, live bandwidth telemetry, and instant threat alerting for local network administrators.

---

### Chapter 3: System Requirements & Feasibility Analysis
- **3.1 Feasibility Study**:
  - *Technical Feasibility*: Evaluation of Python Scapy / raw sockets, FastAPI/Node backend, MongoDB NoSQL performance, and React web rendering.
  - *Operational Feasibility*: Usability assessment for system administrators and non-expert security auditors.
  - *Economic Feasibility*: Cost analysis (zero hardware cost; open-source software stack).
- **3.2 Software Requirements Specification (SRS) Summary**:
  - Core functional requirements (Capture, Parsing, Detection, Alerting, Visualization, Persistence).
  - Non-functional requirements (Performance, Latency $< 500\text{ms}$, Memory $< 512\text{MB}$, Security, Reliability).
- **3.3 Software & Development Environment**:
  - Operating System: Windows 10/11 / Linux (Ubuntu/Kali).
  - Runtime: Python 3.10+, Node.js 18+, MongoDB 6.0+.
  - Packet Driver: Npcap / libpcap.

---

### Chapter 4: System Design & Architecture
- **4.1 High-Level Multi-Tier Architecture**: Multi-layered software design (Network Capture Layer, Processing & Detection Layer, Persistence Layer, Gateway Layer, Presentation Layer).
- **4.2 Data Flow Diagrams (DFD)**:
  - *DFD Level 0 (Context Diagram)*: High-level data streams between network, system, and administrator.
  - *DFD Level 1 (Subsystem Deconstruction)*: Capture, Parsing, Detection, Storage, and UI.
  - *DFD Level 2 (Threat Detection Engine Pipeline)*: Stateful sliding windows, rule evaluation, and incident dispatching.
- **4.3 UML Modeling**:
  - *Use Case Diagram*: Actor interactions and use cases.
  - *Class Diagram*: Core object model (`PacketCaptureEngine`, `ProtocolParser`, `ThreatDetectionEngine`, `Alert`, `BandwidthAggregator`).
  - *Sequence Diagrams*: Real-time packet streaming and threat detection notification flows.
  - *Activity Diagram*: Packet processing lifecycle.
- **4.4 Database Design (MongoDB)**:
  - Detailed collection schemas: `devices`, `packet_logs`, `bandwidth_metrics`, `alerts`, `attack_logs`, `users`, `system_settings`.
  - Indexing strategy and TTL auto-purge architecture.

---

### Chapter 5: Implementation Details & Detection Algorithms
- **5.1 Packet Capture & Ingestion Module**: Implementation of non-blocking raw socket sniffing, promiscuous mode, and thread-safe queue buffering.
- **5.2 Protocol Dissection & Normalization**: Header decoding routines for Ethernet, ARP, IPv4, ICMP, TCP, UDP, and application metadata.
- **5.3 Threat Detection Algorithms & Heuristics**:
  - *Port Scan & Stealth Probe Detection Algorithm* (Mathematical model, sliding window logic, pseudocode).
  - *Volumetric DoS Flood Detection Algorithm* (SYN rate and half-open connection ratio math).
  - *ARP Spoofing & MITM Detection Algorithm* (Authoritative IP-MAC binding verification).
  - *Brute-Force Connection Anomaly Heuristics*.
- **5.4 Real-Time WebSocket Streaming & API Gateway**: Implementation of sub-second throttled WebSocket emitters (`Socket.io`) and RESTful endpoints.
- **5.5 Frontend Dashboard Implementation**: React component structure, dynamic chart rendering (Chart.js / Recharts), live virtualized packet tables, and real-time alert toast notifications.

---

### Chapter 6: Testing, Attack Simulations & Result Analysis
- **6.1 Testing Methodology**: QA framework spanning unit, integration, and security simulation testing.
- **6.2 Unit & Integration Test Results**: Test execution logs and coverage summaries.
- **6.3 Attack Simulation & Verification**:
  - *Simulation 1: TCP SYN Port Scan (`nmap -sS`)* $\rightarrow$ Analysis of detection latency, packet capture graph, and alert record.
  - *Simulation 2: TCP NULL / XMAS Stealth Scans* $\rightarrow$ Flag verification and alert generation.
  - *Simulation 3: TCP SYN Flood DoS* $\rightarrow$ Throughput spike analysis and critical alert dispatch.
  - *Simulation 4: ARP Cache Poisoning Attack* $\rightarrow$ MAC conflict detection and immediate alert notification.
- **6.4 Performance & Benchmark Evaluation**:
  - Packet processing throughput (tested at 10,000 pps).
  - System resource utilization (CPU % and Memory footprint over extended runs).
  - End-to-end WebSocket transmission latency ($< 500\text{ms}$).

---

### Chapter 7: Conclusion & Future Scope
- **7.1 Summary of Contributions**: Summary of the developed software system, highlighting successful real-time monitoring, multi-threat detection, and intuitive web visualization without dedicated hardware appliances.
- **7.2 Limitations of Current System**: Dependence on software interface promiscuous capabilities; limitation to single subnet for ARP inspection unless agent deployed per segment.
- **7.3 Future Scope & Enhancements**:
  - Integration of Machine Learning / Deep Learning (e.g., Autoencoders, Isolation Forests) for zero-day anomaly detection.
  - Automated Active Response / IPS integration (e.g., dynamic software firewall rule injection via `iptables` / Windows Defender API).
  - Distributed multi-agent deployment across multiple remote subnets with centralized cloud reporting.

---

## 3. References & Bibliography (IEEE Citation Style)

```text
[1] J. Postel, "Transmission Control Protocol," RFC 793, Internet Engineering Task Force (IETF), Sep. 1981.
[2] D. Plummer, "An Ethernet Address Resolution Protocol," RFC 826, Internet Engineering Task Force (IETF), Nov. 1982.
[3] IEEE Std 830-1998, "IEEE Recommended Practice for Software Requirements Specifications," IEEE Computer Society, 1998.
[4] V. Jacobson, C. Leres, and S. McCanne, "The libpcap interface," Lawrence Berkeley Laboratory, Berkeley, CA, 1994.
[5] M. Roesch, "Snort - Lightweight Intrusion Detection for Networks," in Proc. 13th USENIX Conf. on System Administration (LISA '99), 1999, pp. 229–238.
[6] G. Lyon, "Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning," Insecure.Com LLC, 2008.
[7] MongoDB Inc., "MongoDB Manual: Time-to-Live (TTL) Indexes & Time Series Collections," MongoDB Documentation, 2024.
[8] OWASP Foundation, "OWASP Top Ten Web Application Security Risks," Open Web Application Security Project, 2021.
```

---

## 4. Appendices

- **Appendix A**: Software Installation & Setup Guide (Step-by-step instructions to run backend, frontend, and MongoDB).
- **Appendix B**: Sample Configuration Files (`config.json`, `.env.example`).
- **Appendix C**: Attack Simulation Script Code Listings.
