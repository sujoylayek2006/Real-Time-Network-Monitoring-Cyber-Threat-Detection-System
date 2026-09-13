# UML & Data Flow Diagrams (DFD) Specifications
## Real-Time Network Monitoring and Threat Detection System

---

### Overview
This document delivers the formal object-oriented and structured system analysis diagrams for the **Real-Time Network Monitoring and Threat Detection System**. All diagrams are authored using standard **Mermaid.js** syntax for integration into documentation viewers, academic reports, and IDEs.

---

## 1. Use Case Diagram

The Use Case Diagram defines the interactions between human actors (System Administrator, Security Analyst), external network traffic, and system components.

```mermaid
flowchart TD
    subgraph Actors
        Admin(("👤 Administrator"))
        Analyst(("👤 Security Analyst"))
        Network(("🌐 Local Network Traffic"))
    end

    subgraph SystemBoundary ["Real-Time Network Monitoring & Threat Detection System"]
        UC1(["Select Network Interface (NIC)"])
        UC2(["Start / Pause Packet Capture"])
        UC3(["View Live Bandwidth & Throughput"])
        UC4(["Inspect Live Packet Stream"])
        UC5(["View Active Device Inventory"])
        UC6(["Receive Real-Time Threat Alerts"])
        UC7(["Filter & Search Incident Logs"])
        UC8(["Acknowledge / Resolve Alerts"])
        UC9(["Configure Threat Thresholds"])
        UC10(["Export Security Incident Report"])
        UC11(["Passively Sniff Raw Frames"])
    end

    Admin --> UC1
    Admin --> UC2
    Admin --> UC9
    Admin --> UC10
    Admin --> UC8

    Analyst --> UC3
    Analyst --> UC4
    Analyst --> UC5
    Analyst --> UC6
    Analyst --> UC7
    Analyst --> UC8

    Network -.-> UC11
    UC11 -.-> UC4
    UC11 -.-> UC6
```

---

## 2. Class Diagram (Object-Oriented Design)

Represents the core software classes, their attributes, methods, and relationships.

```mermaid
classDiagram
    class PacketCaptureEngine {
        -String interfaceName
        -String bpfFilter
        -Boolean isCapturing
        -Queue packetQueue
        +startCapture()
        +stopCapture()
        +listInterfaces() List~String~
        +setFilter(String filter)
    }

    class ProtocolParser {
        +parseEthernet(byte[] raw) EthernetFrame
        +parseIPv4(byte[] raw) IPv4Packet
        +parseTCP(byte[] raw) TCPSegment
        +parseUDP(byte[] raw) UDPDatagram
        +parseARP(byte[] raw) ARPPacket
        +normalize(byte[] raw) NormalizedPacket
    }

    class NormalizedPacket {
        +DateTime timestamp
        +String srcMac
        +String dstMac
        +String srcIp
        +String dstIp
        +String protocol
        +Int srcPort
        +Int dstPort
        +Map tcpFlags
        +Int payloadLength
    }

    class ThreatDetectionEngine {
        -Map slidingWindows
        -List~IRule~ activeRules
        +registerRule(IRule rule)
        +evaluatePacket(NormalizedPacket packet) List~Alert~
        +updateSlidingWindow(String ip, NormalizedPacket packet)
    }

    class IRule {
        <<interface>>
        +evaluate(NormalizedPacket p, Map context) Alert
        +getRuleName() String
    }

    class PortScanRule {
        -Int distinctPortThreshold
        -Int windowSeconds
        +evaluate(NormalizedPacket p, Map context) Alert
    }

    class DoSFloodRule {
        -Int ppsThreshold
        -Float synAckRatioLimit
        +evaluate(NormalizedPacket p, Map context) Alert
    }

    class ARPSpoofRule {
        -Map knownIpMacMap
        +evaluate(NormalizedPacket p, Map context) Alert
    }

    class Alert {
        +String alertId
        +DateTime timestamp
        +String threatType
        +String severity
        +String sourceIp
        +String description
        +String status
        +acknowledge(String user)
        +resolve()
    }

    class BandwidthAggregator {
        -Long totalBytesIn
        -Long totalBytesOut
        -Map protocolBytes
        +ingest(NormalizedPacket p)
        +getOneSecondMetrics() MetricsPayload
        +resetCounters()
    }

    class DeviceManager {
        -Map~String, Device~ deviceMap
        +updateDevice(NormalizedPacket p)
        +getActiveDevices() List~Device~
    }

    class WebSocketGateway {
        +broadcastPacket(NormalizedPacket p)
        +broadcastAlert(Alert a)
        +broadcastMetrics(MetricsPayload m)
    }

    PacketCaptureEngine --> ProtocolParser : feeds raw frames
    ProtocolParser --> NormalizedPacket : creates
    ThreatDetectionEngine --> IRule : executes
    IRule <|.. PortScanRule : implements
    IRule <|.. DoSFloodRule : implements
    IRule <|.. ARPSpoofRule : implements
    ThreatDetectionEngine --> Alert : triggers
    ThreatDetectionEngine --> NormalizedPacket : inspects
    BandwidthAggregator --> NormalizedPacket : records
    DeviceManager --> NormalizedPacket : updates
    WebSocketGateway <.. Alert : transmits
    WebSocketGateway <.. BandwidthAggregator : transmits
```

---

## 3. Sequence Diagrams

### 3.1 Live Packet Capture & Real-Time Streaming Sequence
```mermaid
sequenceDiagram
    autonumber
    actor User as Admin / Analyst (Browser)
    participant UI as React Web Dashboard
    participant WS as WebSocket Server
    participant Capture as PacketCaptureEngine
    participant Parser as ProtocolParser
    participant Aggregator as BandwidthAggregator

    User->>UI: Selects NIC & clicks "Start Capture"
    UI->>WS: Emit("start_capture", { interface: "eth0" })
    WS->>Capture: startCapture("eth0")
    
    loop Real-Time Packet Stream (Async)
        Capture->>Parser: Deliver Raw Frame Bytes
        Parser->>Parser: Decode Headers (L2, L3, L4)
        Parser->>Aggregator: Update Byte Counters
        Parser->>WS: Enqueue Normalized Packet
    end

    loop Every 100ms
        WS->>UI: Emit("packet:stream", [packetsArray])
        UI->>UI: Append rows to Live Packet Grid
    end

    loop Every 1000ms (1 Second)
        Aggregator->>WS: Get aggregated Bps & Protocol %
        WS->>UI: Emit("metrics:update", metricsData)
        UI->>UI: Update Bandwidth Chart & Stat Badges
    end
```

---

### 3.2 Threat Detection & Security Alert Sequence
```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Attacker Machine
    participant NIC as Host Software NIC
    participant Engine as ThreatDetectionEngine
    participant DB as MongoDB
    participant WS as WebSocket Gateway
    actor Admin as Admin (Web Dashboard)

    Attacker->>NIC: Launches TCP SYN Scan (e.g., nmap -sS)
    NIC->>Engine: Ingest Rapid SYN Packets (Ports 21, 22, 80, 443...)
    
    Engine->>Engine: Track distinct ports in sliding window for Attacker IP
    Engine->>Engine: Distinct Ports > 20 in 5s (Threshold Exceeded)
    
    Engine->>DB: Save Alert to "alerts" & "attack_logs" Collections
    Engine->>WS: Emit("alert:new", { threat: "PORT_SCAN_DETECTED", severity: "HIGH" })
    WS->>Admin: Push Alert Toaster + Visual Red Badge + Audio Chime
    
    Admin->>WS: Clicks "Acknowledge Alert"
    WS->>DB: Update Alert Status -> "ACKNOWLEDGED"
```

---

## 4. Activity Diagram: Packet Processing Lifecycle

```mermaid
flowchart TD
    Start([Start Sniffer]) --> Capture[Capture Raw Ethernet Frame from OS NIC]
    Capture --> CheckNull{Is Frame Valid?}
    CheckNull -- No --> Drop[Drop Frame & Increment Error Counter]
    Drop --> Capture
    CheckNull -- Yes --> ParseHeaders[Parse L2 Ethernet / ARP, L3 IP, L4 TCP/UDP Headers]
    
    ParseHeaders --> UpdateStats[Update Bandwidth Counters & Host IP-MAC Registry]
    
    UpdateStats --> EvalThreats[Pass to Threat Detection Rules Engine]
    
    EvalThreats --> CheckThreat{Threat Condition Met?}
    
    CheckThreat -- Yes --> GenAlert[Generate Alert Object with Severity]
    GenAlert --> SaveAlertDB[(Save to MongoDB 'alerts' & 'attack_logs')]
    SaveAlertDB --> PushWSAlert[Push Instant Alert via WebSocket to UI]
    
    CheckThreat -- No --> BufferPacket[Add to 100ms Batch Queue]
    PushWSAlert --> BufferPacket
    
    BufferPacket --> FlushCheck{Batch Ready or 100ms Elapsed?}
    FlushCheck -- Yes --> StreamUI[Stream Packet Batch to Web Dashboard]
    FlushCheck -- No --> Capture
    StreamUI --> Capture
```

---

## 5. Data Flow Diagrams (DFD)

### 5.1 DFD Level 0 (Context Diagram)

The Context Diagram defines the system boundary, external entities, and high-level data streams.

```mermaid
flowchart LR
    NetworkTraffic["🌐 Local Network\n(Packet Traffic)"]
    AdminUser["👤 System Administrator\n/ Security Analyst"]
    System[("⚙️ 0.0\nReal-Time Network\nMonitoring &\nThreat Detection\nSystem")]

    NetworkTraffic -->|"Raw Network Packets (L2/L3/L4)"| System
    AdminUser -->|"Capture Commands, NIC Selection, Threshold Config"| System
    
    System -->|"Live Bandwidth Telemetry, Packet Stream"| AdminUser
    System -->|"Real-Time Security Threat Alerts & Incidents"| AdminUser
    System -->|"Device Inventory & Forensic Audit Reports"| AdminUser
```

---

### 5.2 DFD Level 1 (Subsystem Deconstruction)

Deconstructs the system into its primary functional processes and data stores.

```mermaid
flowchart TD
    NIC["🌐 Host Network Interface"]
    Admin["👤 Administrator"]

    P1["1.0\nPacket Ingestion\n& Sniffing"]
    P2["2.0\nProtocol\nDissection"]
    P3["3.0\nBandwidth &\nDevice Tracking"]
    P4["4.0\nThreat\nDetection Engine"]
    P5["5.0\nAlert &\nNotification Mgr"]
    P6["6.0\nDashboard &\nAPI Gateway"]

    D1[("D1: Packet Logs (TTL 24h)")]
    D2[("D2: Bandwidth Metrics")]
    D3[("D3: Device Inventory")]
    D4[("D4: Alerts & Attack Logs")]
    D5[("D5: System Config")]

    NIC -->|"Raw Ethernet Frames"| P1
    Admin -->|"Start/Stop, Filters"| P1
    Admin -->|"Config Thresholds"| D5
    D5 -->|"Read Thresholds"| P4

    P1 -->|"Raw Byte Stream"| P2
    P2 -->|"Normalized Packet"| P3
    P2 -->|"Normalized Packet"| P4
    P2 -->|"Sampled Packet Headers"| D1

    P3 -->|"Update Device State"| D3
    P3 -->|"1-Min Rollup Stats"| D2
    P3 -->|"Live Metrics Stream"| P6

    P4 -->|"Threat Incident Event"| P5
    P5 -->|"Persist Alert Record"| D4
    P5 -->|"Instant Push Alert"| P6

    P6 -->|"WebSocket Live Stream & REST API"| Admin
    D4 -->|"Historical Query Logs"| P6
    D3 -->|"Active Hosts List"| P6
```

---

### 5.3 DFD Level 2 (Threat Detection & Analysis Subsystem)

Deep dive into Process 4.0 (Threat Detection Engine).

```mermaid
flowchart TD
    InPacket["Normalized Packet Stream"] --> Splitter{"Inspect Protocol & Flags"}

    Splitter -->|"TCP SYN / FIN / NULL / XMAS"| P4_1["4.1\nPort Scan &\nStealth Probe Detector"]
    Splitter -->|"High Volume SYN / UDP / ICMP"| P4_2["4.2\nVolumetric DoS\nFlood Detector"]
    Splitter -->|"ARP Opcode 1/2"| P4_3["4.3\nARP Spoofing &\nPoisoning Detector"]
    Splitter -->|"Auth Ports (22, 21, 3389...)"| P4_4["4.4\nBrute Force\nConnection Detector"]

    SlidingStore[("In-Memory Sliding Windows\n(Per-IP State / Ring Deques)")]

    P4_1 <-->|"Track Distinct Dst Ports"| SlidingStore
    P4_2 <-->|"Track SYN/ACK Ratios & pps"| SlidingStore
    P4_3 <-->|"Validate IP-MAC Bindings"| SlidingStore
    P4_4 <-->|"Track Failed Connection Resets"| SlidingStore

    P4_1 -->|"Scan Threshold Exceeded"| AlertGen["4.5\nIncident Aggregator &\nSeverity Formatter"]
    P4_2 -->|"Flood Limit Exceeded"| AlertGen
    P4_3 -->|"MAC Conflict Detected"| AlertGen
    P4_4 -->|"Brute Force Pattern Matched"| AlertGen

    AlertGen --> OutAlert["Dispatched Security Alert Object"]
```

---

## 6. Entity-Relationship (ER) Diagram

Represents the data entities, attributes, and relationships stored in MongoDB.

```mermaid
erDiagram
    USERS ||--o{ ALERTS : acknowledges
    DEVICES ||--o{ PACKET_LOGS : generates
    ALERTS ||--|| ATTACK_LOGS : contains_forensics
    SYSTEM_SETTINGS ||--o{ ALERTS : configures_thresholds

    DEVICES {
        ObjectId _id PK
        string mac_address UK
        string ip_address
        string hostname
        string vendor
        datetime first_seen
        datetime last_seen
        int64 total_bytes_sent
        int64 total_bytes_received
        string status
    }

    PACKET_LOGS {
        ObjectId _id PK
        datetime timestamp
        string interface
        string src_mac
        string dst_mac
        string src_ip
        string dst_ip
        string protocol
        int src_port
        int dst_port
        int payload_size_bytes
    }

    BANDWIDTH_METRICS {
        ObjectId _id PK
        datetime timestamp
        int duration_seconds
        int64 total_bytes
        int total_packets
        float avg_mbps
        json protocol_breakdown
    }

    ALERTS {
        ObjectId _id PK
        datetime timestamp
        string threat_type
        string category
        string severity
        string source_ip
        string target_ip
        string description
        string status
        ObjectId acknowledged_by FK
    }

    ATTACK_LOGS {
        ObjectId _id PK
        ObjectId alert_id FK
        datetime timestamp
        string attack_name
        string attacker_ip
        string victim_ip
        json packet_sample
        json metrics_at_attack
        string forensic_notes
    }

    USERS {
        ObjectId _id PK
        string username UK
        string email
        string password_hash
        string role
        boolean is_active
    }

    SYSTEM_SETTINGS {
        ObjectId _id PK
        string selected_interface
        json thresholds
        json alert_notifications
    }
```
