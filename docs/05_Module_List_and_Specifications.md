# System Module List & Technical Specifications
## Real-Time Network Monitoring and Threat Detection System

---

### Overview
This document defines the complete functional modular breakdown for the **Real-Time Network Monitoring and Threat Detection System**. The software is organized into 10 decoupled, high-cohesion modules spanning the capture engine, detection core, persistence layer, API gateway, and interactive user interface.

---

## 1. Master Module Inventory

| Module ID | Module Name | Primary Responsibility | Tech Stack / Components |
| :--- | :--- | :--- | :--- |
| **MOD-01** | Packet Capture & Ingestion Engine | Intercepts raw frames from software network adapters | Python Scapy / `libpcap` / Raw Sockets |
| **MOD-02** | Protocol Dissector & Normalizer | Decodes L2/L3/L4/L7 headers and standardizes schema | Custom Binary Parser & Bitwise Decoders |
| **MOD-03** | Bandwidth & Telemetry Aggregator | Calculates rolling Bps, pps, throughput & protocol % | In-Memory Sliding Window Accumulator |
| **MOD-04** | Host Discovery & Device Inventory | Identifies active subnet hosts, maps IP-MAC bindings | In-Memory Hash Registry & ARP Watcher |
| **MOD-05** | Threat Detection & Heuristic Core | Evaluates packets against attack rules & anomaly models| Rule-Based Heuristics & Sliding Windows |
| **MOD-06** | Alert Dispatcher & Incident Manager | Generates structured alerts with remediation guidance | Event Bus & Incident State Machine |
| **MOD-07** | Historical Forensics & Persistence | Queries and stores logs, applies TTL expiration | MongoDB & Mongoose / Motor Driver |
| **MOD-08** | API Gateway & WebSocket Server | Exposes REST endpoints and manages live socket feeds | FastAPI / Express & Socket.io |
| **MOD-09** | Interactive Web Dashboard UI | Visualizes live telemetry, charts, grids & alert feeds | React.js / Modern Web UI & Tailwind CSS |
| **MOD-10** | Authentication & System Settings | Admin auth, JWT tokens, RBAC & threshold tuning | JWT, bcrypt, Config Store |

---

## 2. Detailed Technical Specifications per Module

### 2.1 MOD-01: Packet Capture & Ingestion Engine
- **Purpose**: Low-latency, non-blocking capture of raw Ethernet frames directly from OS software network interfaces.
- **Key Classes / Functions**:
  - `InterfaceManager.get_available_interfaces()`: Queries the host OS for network adapters (friendly name, MAC, IP, MTU).
  - `PacketSniffer.start_capture(interface, bpf_filter)`: Spawns an asynchronous background thread utilizing raw socket sniffing.
  - `PacketSniffer.stop_capture()`: Gracefully halts thread and drains pending buffers.
- **Data Flow**:
  - **Input**: Raw binary stream from OS software NIC.
  - **Output**: Bounded in-memory FIFO queue (`queue.Queue`) of timestamped raw byte buffers.
- **Error Handling**: Handles interface disconnects, insufficient root/admin permission exceptions, and frame buffer overflows.

---

### 2.2 MOD-02: Protocol Dissector & Normalizer
- **Purpose**: Deconstructs raw binary frames into structured, JSON-serializable normalized packet objects.
- **Supported Protocols**:
  - **Layer 2**: Ethernet II (MACs, EtherType), ARP (Opcode, Sender/Target IP & MAC).
  - **Layer 3**: IPv4 / IPv6 (Source/Dest IP, TTL, Header Length, Protocol ID, Total Length), ICMP (Type, Code, ID, Seq).
  - **Layer 4**: TCP (Source/Dest Port, Seq/Ack, Flags: SYN/ACK/FIN/RST/PSH/URG, Window Size), UDP (Source/Dest Port, Length, Checksum).
  - **Layer 7**: HTTP (Method, Host, URI, Status Code), DNS (Query Name, Query Type, Response Code).
- **Normalized Schema Example**:
  ```typescript
  interface NormalizedPacket {
    timestamp: Date;
    interface: string;
    l2: { src_mac: string; dst_mac: string; ethertype: string };
    l3: { src_ip: string; dst_ip: string; protocol: string; ttl: number; length: number };
    l4: { src_port?: number; dst_port?: number; tcp_flags?: TCPFlags; length?: number };
    payload_preview?: string;
  }
  ```

---

### 2.3 MOD-03: Bandwidth & Telemetry Aggregator
- **Purpose**: Computes rolling metrics at sub-second intervals for real-time throughput rendering.
- **Core Operations**:
  - Increments cumulative byte and packet counters per protocol type.
  - Calculates 1-second rolling download/upload rates:
    $$\text{Throughput (Mbps)} = \frac{\Delta \text{Bytes} \times 8}{1,000,000 \times \Delta t}$$
  - Generates protocol percentage distributions (TCP%, UDP%, ICMP%, ARP%).
  - Detects abrupt volumetric traffic spikes exceeding $3\sigma$ (standard deviations) from moving averages.

---

### 2.4 MOD-04: Host Discovery & Device Inventory
- **Purpose**: Passively discovers all active computing devices communicating over the local network subnet.
- **Core Operations**:
  - Extracts `(src_mac, src_ip)` tuples from all observed frames.
  - Resolves Organizationally Unique Identifier (OUI) vendor lookups from MAC prefixes.
  - Maintains host metadata: `first_seen`, `last_seen`, `bytes_sent`, `bytes_received`, `active_state`.
  - Flags devices that exhibit suspicious port scan or flooding behaviors.

---

### 2.5 MOD-05: Threat Detection & Heuristic Core
- **Purpose**: Analyzes the normalized packet stream in real time to identify malicious cyber activities and security anomalies.
- **Detection Sub-Engines**:
  1. **Port Scan Analyzer**: Tracks distinct destination ports contacted per source IP over a rolling 5-second window.
  2. **Stealth Scan Detector**: Identifies illegal TCP flag combinations (NULL scans `0x00`, XMAS scans `0x29`, unsolicited FIN packets).
  3. **DoS / DDoS Flood Detector**: Computes SYN/ACK completion ratios and monitors per-second packet thresholds for SYN, UDP, and ICMP streams.
  4. **ARP Poisoning Detector**: Maintains an authoritative IP-to-MAC mapping cache; flags any gratuitous or conflicting ARP reply that attempts to remap an existing IP address.
  5. **Brute-Force Connection Analyzer**: Inspects high-frequency connection terminations and TCP RST responses on standard service ports (21, 22, 3389, 80, 443).

---

### 2.6 MOD-06: Alert Dispatcher & Incident Manager
- **Purpose**: Formulates actionable incident alerts, assigns severity tiers, attaches remediation guidelines, and pushes notifications.
- **Severity Classification Matrix**:
  - **CRITICAL**: Active SYN Flood DoS, Ongoing ARP Cache Poisoning (Man-In-The-Middle threat).
  - **HIGH**: Rapid Port Sweep / Port Scan, Repeated Brute Force attempts.
  - **MEDIUM**: Stealth TCP Scan (NULL/XMAS), Unusual Bandwidth Spike.
  - **LOW**: Isolated unknown protocol packet, ICMP echo burst.
- **State Transition Flow**:
  $$\text{NEW} \xrightarrow{\text{Admin clicks Review}} \text{ACKNOWLEDGED} \xrightarrow{\text{Threat Blocked/Resolved}} \text{RESOLVED}$$

---

### 2.7 MOD-07: Historical Forensics & Persistence
- **Purpose**: Manages long-term storage and high-speed retrieval of security incident records, metrics, and raw packet metadata.
- **Key Operations**:
  - Executes batch inserts for high-throughput packet metadata into MongoDB.
  - Manages MongoDB TTL indexes (24-hour auto-expiration for raw packet documents).
  - Provides indexed multi-parameter query builders supporting filters by IP, protocol, port, severity, and ISO datetime ranges.
  - Generates downloadable CSV / JSON export dumps for academic submission and forensic reporting.

---

### 2.8 MOD-08: API Gateway & WebSocket Server
- **Purpose**: Serves as the central communication bridge connecting backend detection workers with the client web dashboard.
- **REST Endpoints**:
  - `GET /api/v1/system/status`: Returns current capture status, CPU/RAM usage, and active NIC.
  - `POST /api/v1/capture/start`: Starts packet capture on specified adapter.
  - `POST /api/v1/capture/stop`: Halts active packet capture.
  - `GET /api/v1/alerts`: Returns paginated list of security alerts with filter queries.
  - `PATCH /api/v1/alerts/:id`: Updates alert status (`ACKNOWLEDGED` / `RESOLVED`).
  - `GET /api/v1/devices`: Returns active device inventory list.
  - `GET /api/v1/config/thresholds`: Returns current detection threshold parameters.
  - `PUT /api/v1/config/thresholds`: Updates threshold parameters dynamically.
- **WebSocket Feeds (`Socket.io`)**:
  - `packet:stream`: Emits throttled arrays of packet objects (100ms).
  - `metrics:update`: Emits 1-second rolling bandwidth telemetry.
  - `alert:new`: Broadcasts instant high-priority threat alert payload.

---

### 2.9 MOD-09: Interactive Web Dashboard UI
- **Purpose**: Provides a modern, responsive, dark-mode user interface for real-time visualization, attack monitoring, and administrative control.
- **Key UI Views**:
  1. **Overview Dashboard**: Stat summary cards (Total Packets, Active Threats, Throughput Mbps, Active Hosts), live bandwidth chart, and protocol breakdown donut.
  2. **Live Packet Stream**: High-performance virtualized data table displaying live incoming frames with pause/resume controls and search filters.
  3. **Threat Center & Alerts**: Live alert cards with severity badges, sound notifications, and one-click incident acknowledgment.
  4. **Device Explorer**: Grid of active network endpoints displaying MAC vendor, IP, bytes sent/received, and threat status.
  5. **Forensic Log Query Engine**: Historical search console with date pickers, IP filters, and export buttons.
  6. **Settings Panel**: Interface selector dropdown, BPF filter input, and detection threshold sliders.

---

### 2.10 MOD-10: Authentication & System Settings
- **Purpose**: Enforces access security, user identity verification, and runtime system configuration.
- **Features**:
  - JWT token generation with expiration and secure HTTP-only cookies.
  - Password hashing utilizing `bcrypt` (12 rounds).
  - Role-based authorization middleware protecting administrative endpoints.
  - System configuration persistence in MongoDB.
