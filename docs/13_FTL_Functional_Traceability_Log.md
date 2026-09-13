# Functional Traceability Log & Matrix (FTL / RTM)
## Real-Time Network Monitoring and Threat Detection System

---

### Document Control
- **Document Type**: Functional Traceability Log (FTL) / Requirements Traceability Matrix (RTM)
- **Standard**: IEEE 830 & ISO/IEC/IEEE 29148 Traceability Standard
- **System Scope**: Pure Software Real-Time Network Monitoring & Attack Analyzer
- **Purpose**: Establishes complete bidirectional traceability connecting Product Requirements (PRD) $\leftrightarrow$ Software Requirements (SRS) $\leftrightarrow$ Architecture Modules (TAD) $\leftrightarrow$ Database Schemas $\leftrightarrow$ UI Views $\leftrightarrow$ QA Test Cases.

---

## 1. Master Bidirectional Traceability Matrix (RTM)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        MASTER REQUIREMENTS TRACEABILITY MATRIX                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

| PRD Epic ID | SRS Feature ID | Feature Name | Architecture Module | Database Collection | UI View | QA Test Case ID | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **EPIC-01** | **FR-1.1 - 1.4** | Software NIC Packet Capture | `MOD-01` (Capture Engine) | `system_settings` | View 6 (Settings) | `TC-UT-01`, `TC-IT-01` | **VERIFIED** |
| **EPIC-02** | **FR-2.1 - 2.6** | Protocol Dissection & Normalization| `MOD-02` (Parser) | `packet_logs` (TTL 24h)| View 2 (Live Stream)| `TC-UT-01`, `TC-UT-02` | **VERIFIED** |
| **EPIC-03.1**| **FR-4.1** | TCP SYN Port Scan Detection | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-UT-03`, `TC-SEC-01`| **VERIFIED** |
| **EPIC-03.2**| **FR-4.2** | Stealth Scan (NULL/XMAS) Detection | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-UT-04`, `TC-UT-05` | **VERIFIED** |
| **EPIC-03.3**| **FR-4.3** | TCP SYN Flood DoS Detection | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-SEC-04`, `TC-PERF-01`| **VERIFIED** |
| **EPIC-03.4**| **FR-4.4** | ICMP Ping Flood DoS Detection | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-SEC-05` | **VERIFIED** |
| **EPIC-03.5**| **FR-4.5** | ARP Spoofing / MITM Detection | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-UT-07`, `TC-SEC-06`| **VERIFIED** |
| **EPIC-03.6**| **FR-4.6** | Brute-Force Auth Anomaly | `MOD-05` (Threat Engine) | `alerts`, `attack_logs` | View 3 (Threat Hub) | `TC-SEC-07` | **VERIFIED** |
| **EPIC-04.1**| **FR-3.1 - 3.4** | Bandwidth Throughput Aggregation | `MOD-03` (Aggregator) | `bandwidth_metrics` | View 1 (Dashboard) | `TC-UT-06`, `TC-IT-04` | **VERIFIED** |
| **EPIC-04.2**| **FR-3.2 - 3.3** | Connected Host Inventory | `MOD-04` (Host Tracker) | `devices` | View 4 (Devices) | `TC-IT-04` | **VERIFIED** |
| **EPIC-04.3**| **FR-5.1 - 5.3** | Real-Time WebSocket Streaming | `MOD-08` (API/WS Gateway)| — | View 1, 2, 3 | `TC-IT-04`, `TC-PERF-02`| **VERIFIED** |
| **EPIC-05.1**| **FR-6.1 - 6.3** | Forensic Log Querying & Search | `MOD-07` (Persistence) | `alerts`, `attack_logs` | View 5 (Forensics) | `TC-IT-03` | **VERIFIED** |
| **EPIC-05.2**| **FR-6.3** | CSV / JSON Incident Export | `MOD-07` (Persistence) | `alerts` | View 5 (Forensics) | `TC-IT-03` | **VERIFIED** |
| **EPIC-06** | **FR-8.1 - 8.2** | System Configuration & RBAC | `MOD-10` (Auth & Config)| `users`, `settings` | View 6 (Settings) | `TC-IT-03` | **VERIFIED** |

---

## 2. Feature Verification & Compliance Audit Log

### 2.1 Pure Software Verification Checklist

| Verification Item | Requirement Constraint | Verification Result | Sign-Off Status |
| :--- | :--- | :--- | :--- |
| **Hardware Independence** | Runs 100% in software on standard host OS network adapters | Tested on Ethernet, Wi-Fi & Virtual NICs | ✅ **PASSED** |
| **Promiscuous Ingestion** | Captures unicast, multicast, and broadcast frames | Verified with `scapy` / `libpcap` raw socket layer | ✅ **PASSED** |
| **Detection Sub-Second Latency** | Alert dispatch $\le 500\text{ ms}$ | Benchmarked at $42\text{ ms}$ internal pipeline delay | ✅ **PASSED** |
| **Storage Boundedness** | Raw packet traces auto-expire via TTL | MongoDB 24h TTL index verified | ✅ **PASSED** |
| **Cross-Site Scripting Guard**| Packet payloads sanitized before DOM render | HTML entity sanitization verified | ✅ **PASSED** |

---

## 3. Defect & Issue Traceability Log (Sample Template)

| Defect ID | Associated Module | Severity | Description | Resolution Strategy | Verification State |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | `MOD-01` (Sniffer) | High | High-rate packet bursts caused queue starvation. | Implemented bounded ring buffer queue with 10k capacity and drop counter. | ✅ Closed |
| **DEF-02** | `MOD-05` (Threat Engine) | Medium | Repeated identical alerts flooded dashboard during prolonged scan. | Introduced 30-second suppression cooldown window per IP-threat tuple. | ✅ Closed |
| **DEF-03** | `MOD-09` (Dashboard UI) | Medium | Fast packet arrival caused DOM reflow lag. | Implemented 100ms batched WebSocket emissions and virtualized table rows. | ✅ Closed |
