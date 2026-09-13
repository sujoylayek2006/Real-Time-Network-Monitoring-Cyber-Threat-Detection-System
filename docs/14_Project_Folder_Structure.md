# Project Folder Structure & Codebase Organization
## Real-Time Network Monitoring and Threat Detection System
*(Web-Based Network Monitoring and Network Attack Analyzer)*

---

### Document Overview
This document defines the complete directory tree, module organization, file naming conventions, and structural architecture for the **Real-Time Network Monitoring and Threat Detection System**. 

The codebase is organized into a clean, decoupled full-stack architecture separating the **Capture & Threat Analysis Engine**, **Persistence Layer**, **API & Real-Time Gateway**, and the **React Dashboard User Interface**.

---

## 1. Master Directory Tree Structure

```text
Collage Project/
├── .gitignore
├── .env.example
├── README.md
├── docker-compose.yml
│
├── docs/                                  # Complete Pre-Development Documentation Suite
│   ├── 01_SRS_Document.md                 # IEEE 830 Software Requirements Specification
│   ├── 02_System_Architecture.md          # Multi-Tier System Architecture & Pipelines
│   ├── 03_MongoDB_Database_Design.md      # Schemas, Indexes, TTLs & Aggregations
│   ├── 04_UML_and_DFD_Diagrams.md         # Mermaid Use Case, Class, Sequence, DFDs, ER
│   ├── 05_Module_List_and_Specifications.md# 10 Core Modules Technical Breakdown
│   ├── 06_Security_and_Attack_Detection_Specifications.md # Attack Heuristics & Rules
│   ├── 07_Testing_Documentation.md        # Test Strategy, Matrix & Simulation Guides
│   ├── 08_30_Day_Development_Plan.md      # Sprint Milestones & Day-by-Day Roadmap
│   ├── 09_Final_Project_Report_Structure.md # Academic Thesis & University Format
│   ├── 10_UI_UX_Design_Specification.md   # Design Tokens, Wireframes & SOC Dark Theme
│   ├── 11_PRD_Product_Requirements_Document.md # Product Specs, User Stories & KPIs
│   ├── 12_TAD_Technical_Architecture_Document.md # Deep Low-Level Concurrency & Specs
│   ├── 13_FTL_Functional_Traceability_Log.md # Bidirectional RTM & Audit Checklist
│   └── 14_Project_Folder_Structure.md     # (This Document) Codebase Directory Map
│
├── backend/                               # Python / Node.js Real-Time Engine & API
│   ├── requirements.txt                   # Python dependencies (scapy, fastapi, uvicorn, pymongo)
│   ├── package.json                       # (Optional Node.js server dependencies)
│   ├── main.py                            # Server entrypoint & lifespan initializer
│   ├── config.py                          # Global settings, environment variables & defaults
│   │
│   ├── capture/                           # 1. Packet Sniffing & Ingestion Layer
│   │   ├── __init__.py
│   │   ├── sniffer_worker.py              # Asynchronous raw socket/scapy capture worker thread
│   │   ├── interface_manager.py           # OS Network Adapter enumerator & selector
│   │   └── buffer_queue.py                # Bounded thread-safe ring buffer queue (10k pkts)
│   │
│   ├── parser/                            # 2. Protocol Dissection Layer
│   │   ├── __init__.py
│   │   ├── dissector.py                   # Master multi-layer protocol decoder
│   │   ├── l2_ethernet.py                 # Layer 2: Ethernet II & ARP decoder
│   │   ├── l3_ip.py                       # Layer 3: IPv4, IPv6 & ICMP header decoder
│   │   └── l4_tcp_udp.py                  # Layer 4: TCP flags & UDP datagram decoder
│   │
│   ├── analytics/                         # 3. Aggregation & Device Tracking Layer
│   │   ├── __init__.py
│   │   ├── bandwidth_aggregator.py        # 1-second rolling Bps, pps & protocol % accumulator
│   │   └── device_tracker.py              # In-memory IP/MAC registry & vendor resolver
│   │
│   ├── detection/                         # 4. Threat & Heuristic Detection Core
│   │   ├── __init__.py
│   │   ├── engine.py                      # Threat engine coordinator & sliding window state
│   │   ├── base_rule.py                   # Pluggable IRule abstract interface
│   │   ├── rules/                         # Modular threat detection heuristics
│   │   │   ├── __init__.py
│   │   │   ├── port_scan_rule.py          # TCP SYN, UDP port sweep heuristics
│   │   │   ├── stealth_scan_rule.py       # TCP NULL (0x00) & XMAS (0x29) flag rules
│   │   │   ├── dos_flood_rule.py          # SYN flood ratio & ICMP/UDP rate limits
│   │   │   ├── arp_spoof_rule.py          # Dynamic IP-MAC conflict & MITM detector
│   │   │   ├── brute_force_rule.py        # Rapid RST & failed auth connection rules
│   │   │   └── traffic_spike_rule.py      # Statistical Z-Score volumetric anomaly rule
│   │   └── alert_formatter.py             # Severity calculator & mitigation advice builder
│   │
│   ├── database/                          # 5. MongoDB Persistence Layer
│   │   ├── __init__.py
│   │   ├── connection.py                  # MongoDB client pool & lifecycle manager
│   │   ├── models/                        # Document schemas & validation definitions
│   │   │   ├── __init__.py
│   │   │   ├── packet_model.py            # Raw packet schema (with 24h TTL index)
│   │   │   ├── alert_model.py             # Security incident alert schema
│   │   │   ├── attack_log_model.py        # Forensic packet dump schema
│   │   │   ├── device_model.py            # Known host schema
│   │   │   ├── metric_model.py            # 1-min aggregated metric schema (30d TTL)
│   │   │   └── user_model.py              # Admin credentials & RBAC schema
│   │   └── repositories/                  # Data access objects (DAOs) & query builders
│   │       ├── __init__.py
│   │       ├── alert_repo.py              # Alert query, filter & status updater
│   │       └── forensic_repo.py           # Historical packet search & CSV exporter
│   │
│   ├── api/                               # 6. REST API & WebSocket Gateway Layer
│   │   ├── __init__.py
│   │   ├── routes/                        # REST endpoint controllers
│   │   │   ├── __init__.py
│   │   │   ├── system_routes.py           # /api/v1/system (Status, Interfaces, Metrics)
│   │   │   ├── capture_routes.py          # /api/v1/capture (Start, Stop, Pause)
│   │   │   ├── alert_routes.py            # /api/v1/alerts (Get, Filter, Acknowledge)
│   │   │   ├── device_routes.py           # /api/v1/devices (List, Inspect)
│   │   │   ├── config_routes.py           # /api/v1/config (Thresholds, Settings)
│   │   │   └── auth_routes.py             # /api/v1/auth (Login, Register, Token verify)
│   │   ├── middleware/                    # Middleware security & guards
│   │   │   ├── __init__.py
│   │   │   ├── auth_guard.py              # JWT authentication & role-based authorization
│   │   │   └── cors_middleware.py         # Cross-Origin Resource Sharing security
│   │   └── websocket/                     # Real-Time WebSocket Channel
│   │       ├── __init__.py
│   │       ├── socket_server.py           # Socket.io connection manager & event router
│   │       └── broadcasters.py            # Throttled 100ms packet & 1s metrics emitters
│   │
│   └── utils/                             # Shared Helper Utilities
│       ├── __init__.py
│       ├── logger.py                      # Formatted console & file logging
│       ├── sanitizers.py                  # HTML/XSS payload string sanitizer
│       └── oui_database.py                # MAC address vendor prefix lookup table
│
├── frontend/                              # Modern React.js / Next.js Web Dashboard
│   ├── package.json                       # Node dependencies (react, lucide-react, chart.js, socket.io-client)
│   ├── vite.config.js / next.config.js    # Build & bundling configuration
│   ├── tailwind.config.js                 # Tailwind CSS theme & SOC dark-mode tokens
│   ├── postcss.config.js                  # CSS post-processing
│   ├── public/                            # Static assets
│   │   ├── favicon.ico
│   │   ├── logo.svg
│   │   └── sounds/
│   │       └── alert_chime.mp3            # Audio alert notification sound
│   │
│   └── src/                               # Frontend Source Code
│       ├── index.js / main.jsx            # React root mount & providers
│       ├── App.jsx                        # Main routing & layout wrapper
│       ├── index.css                      # Global styles & Glassmorphism design tokens
│       │
│       ├── assets/                        # Icons, SVGs & graphics
│       │
│       ├── components/                    # Reusable UI Components
│       │   ├── common/                    # Base atoms & primitives
│       │   │   ├── Button.jsx             # Styled glassmorphic button
│       │   │   ├── Badge.jsx              # Severity pill badges (Critical, High, Med, Low)
│       │   │   ├── Card.jsx               # Glassmorphic container with glowing borders
│       │   │   ├── Modal.jsx              # Backdrop-blurred modal container
│       │   │   └── Spinner.jsx            # Real-time loading indicator
│       │   │
│       │   ├── layout/                    # Global structure components
│       │   │   ├── Header.jsx             # Top bar: NIC selector, live sniffing badge, sound toggle
│       │   │   ├── Sidebar.jsx            # Left navigation sidebar with route icons
│       │   │   └── StatusBar.jsx          # Bottom status banner (PPS, Buffer %, Socket state)
│       │   │
│       │   ├── dashboard/                 # View 1: Main Real-Time Operations Center
│       │   │   ├── MetricCardsRow.jsx     # Live Stat summary cards (Pkts, Speed, Threats, Hosts)
│       │   │   ├── BandwidthChart.jsx     # Ingress/Egress real-time line chart
│       │   │   ├── ProtocolDonutChart.jsx # Protocol distribution breakdown
│       │   │   └── QuickAlertFeed.jsx     # Compact real-time alert ticker
│       │   │
│       │   ├── packets/                   # View 2: Live Virtualized Packet Stream
│       │   │   ├── PacketStreamTable.jsx  # High-speed virtualized data table
│       │   │   ├── PacketFilterBar.jsx    # IP/Port/Protocol instant search input
│       │   │   └── PacketInspectorModal.jsx # Multi-layer header & hex dump modal
│       │   │
│       │   ├── threats/                   # View 3: Threat Center & Incident Hub
│       │   │   ├── ThreatIncidentCard.jsx # Expandable incident card with severity badge
│       │   │   ├── IncidentActionModal.jsx# Forensics details & one-click firewall copy
│       │   │   └── ThreatFilterTabs.jsx   # Severity & status filter buttons
│       │   │
│       │   ├── devices/                   # View 4: Connected Devices Explorer
│       │   │   ├── DeviceGrid.jsx         # Card grid of discovered subnet hosts
│       │   │   └── DeviceCard.jsx         # Host card (MAC vendor, IP, Tx/Rx bandwidth)
│       │   │
│       │   ├── forensics/                 # View 5: Forensic Historical Log Query Engine
│       │   │   ├── ForensicQueryForm.jsx  # Date pickers, multi-parameter filter form
│       │   │   ├── ForensicResultsTable.jsx # Historical incident data grid
│       │   │   └── ExportReportButtons.jsx# CSV & JSON report export triggers
│       │   │
│       │   └── settings/                  # View 6: System Settings & Detection Tuning
│       │       ├── InterfaceSelector.jsx  # Dropdown for selecting OS network adapter
│       │       ├── ThresholdSliders.jsx   # Interactive sliders for threat sensitivity
│       │       └── NotificationPrefs.jsx  # Audio chime & browser notification toggles
│       │
│       ├── context/                       # Global React State Contexts
│       │   ├── SocketContext.jsx          # WebSocket persistent connection provider
│       │   ├── PacketStreamContext.jsx    # Live streaming packet batch state
│       │   ├── ThreatAlertContext.jsx     # Active alert feed & audio notification state
│       │   └── AuthContext.jsx            # User login state & JWT token storage
│       │
│       ├── hooks/                         # Custom React Hooks
│       │   ├── useWebSocket.js            # Hook for listening to Socket.io events
│       │   ├── useThrottle.js             # High-frequency data throttler
│       │   └── useAudioAlert.js           # Audio playback trigger for high/critical threats
│       │
│       └── services/                      # API Client Services
│           ├── api.js                     # Axios / Fetch base client with JWT interceptor
│           ├── alertService.js            # Endpoints for alerts and acknowledgments
│           ├── systemService.js           # Endpoints for system status and NIC selection
│           └── forensicService.js         # Endpoints for historical logs and CSV exports
│
├── tests/                                 # Test Suite & Attack Simulation Testbed
│   ├── conftest.py                        # Pytest fixtures and mock database setup
│   ├── unit/                              # Unit Tests
│   │   ├── test_dissector.py              # Tests for Ethernet, IP, TCP, UDP header parsing
│   │   ├── test_sliding_window.py         # Tests for sliding window deque eviction
│   │   ├── test_bandwidth_math.py         # Tests for throughput and protocol percentage math
│   │   └── test_heuristics.py             # Tests for Port Scan, DoS, ARP spoof rule logic
│   │
│   ├── integration/                       # Integration Tests
│   │   ├── test_sniffer_to_parser.py      # Tests raw frame buffering through queue
│   │   ├── test_threat_to_db.py           # Tests alert persistence in MongoDB
│   │   └── test_websocket_broadcast.py    # Tests live packet emission to socket clients
│   │
│   ├── simulations/                       # Non-Destructive Attack Simulation Scripts
│   │   ├── test_scans.py                  # Scapy script: SYN scan, NULL scan, XMAS scan
│   │   ├── test_syn_flood.py              # Scapy script: Non-destructive localhost SYN flood
│   │   ├── test_arp_spoof.py              # Scapy script: Conflicting ARP reply generator
│   │   └── test_brute_force.py            # Socket script: Rapid SSH/FTP auth attempts
│   │
│   └── mocks/                             # Mock Data & PCAP Sample Traces
│       ├── sample_traffic.pcap            # Pre-recorded standard web traffic
│       └── sample_port_scan.pcap          # Pre-recorded nmap port scan trace
│
└── scripts/                               # Deployment & Utility Automation
    ├── seed_demo_data.py                  # Pre-loads MongoDB with realistic demo hosts & alerts
    ├── start_backend.bat / .sh            # One-click backend startup script
    ├── start_frontend.bat / .sh           # One-click frontend startup script
    └── run_all.bat / .sh                  # Master orchestrator launching DB, Backend & UI
```

---

## 2. Key Subsystem Responsibilities

### 2.1 Backend Architecture (`/backend`)
- **`capture/`**: Operates at the lowest level, interfacing with `libpcap`/`Npcap` raw sockets to passively read Ethernet frames into a bounded memory buffer.
- **`parser/`**: Deconstructs raw binary frames into standardized Python/JSON dictionaries using bitwise masking.
- **`detection/`**: Stateful analytics engine executing modular threat rules against rolling time-window queues.
- **`database/`**: Asynchronous MongoDB storage layer with automatic 24-hour TTL index purging for raw packets and permanent retention for alerts.
- **`api/`**: FastAPI/Express controllers exposing REST endpoints and Socket.io real-time streaming feeds.

### 2.2 Frontend Architecture (`/frontend`)
- **Atomic Components (`/components`)**: Modular UI elements organized by view (Dashboard, Packet Grid, Threat Hub, Devices, Forensics, Settings).
- **Global Context Providers (`/context`)**: Centralized state management for WebSocket packet feeds, alerts, and user authentication.
- **Custom Hooks (`/hooks`)**: Abstracted socket lifecycle management, data throttling, and audio chime triggers.
- **Styling (`index.css` & `tailwind.config.js`)**: Pure CSS and Tailwind tokens for dark-mode glassmorphism.

### 2.3 Testing & Simulations (`/tests`)
- **`simulations/`**: Standalone, non-destructive Python Scapy scripts that simulate real-world attacks (`nmap` scans, SYN floods, ARP conflicts) for live lab demonstrations and project evaluation vivas.
- **`scripts/seed_demo_data.py`**: Allows instant pre-population of MongoDB with demo hosts, bandwidth graphs, and historical alerts for offline presentation safety.

---

## 3. Naming Conventions & Code Standards

| Element | Convention | Example |
| :--- | :--- | :--- |
| **Python Files & Modules** | `snake_case` | `sniffer_worker.py`, `port_scan_rule.py` |
| **Python Classes** | `PascalCase` | `PacketSniffer`, `ThreatDetectionEngine` |
| **React Components** | `PascalCase.jsx` | `BandwidthChart.jsx`, `PacketInspectorModal.jsx` |
| **React Hooks** | `camelCase.js` (prefix `use`) | `useWebSocket.js`, `useAudioAlert.js` |
| **REST Endpoints** | `kebab-case` / lowercase | `/api/v1/system/status`, `/api/v1/alerts` |
| **WebSocket Events** | `noun:verb` (colon-delimited)| `packet:stream`, `metrics:update`, `alert:new` |
| **MongoDB Collections** | `snake_case` (plural) | `packet_logs`, `bandwidth_metrics`, `alerts` |
