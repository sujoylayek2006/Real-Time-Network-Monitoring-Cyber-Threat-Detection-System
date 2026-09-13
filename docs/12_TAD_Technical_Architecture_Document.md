# Technical Architecture Document (TAD)
## Real-Time Network Monitoring and Threat Detection System
*(Deep-Dive Engineering & Low-Level System Design)*

---

### Document Control
- **Document Type**: Technical Architecture Document (TAD)
- **Target Audience**: Core Software Engineers, Systems Architects, Technical Evaluators
- **System Classification**: High-Throughput Real-Time Network Observability Core
- **Execution Nature**: 100% Pure Software (No dedicated hardware appliances required)

---

## 1. Architectural Paradigm & System Foundation

The **Real-Time Network Monitoring and Threat Detection System** is architected as an **Asynchronous Multi-Threaded Pipeline with an Event-Driven WebSocket Gateway**. It decouples packet capture from analytical computation and user-interface broadcasting to achieve microsecond packet ingestion times and sub-second UI updates.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        LOW-LEVEL CONCURRENCY ARCHITECTURE                              │
│                                                                                        │
│  ┌───────────────────────┐                                                             │
│  │   OS Network Driver   │ (Npcap / Libpcap Promiscuous Raw Sockets)                  │
│  └───────────┬───────────┘                                                             │
│              │ (Raw Ethernet Frames)                                                   │
│              ▼                                                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │  THREAD 1: Packet Sniffer Worker (Producer)                                      │  │
│  │  - Non-blocking socket polling                                                   │  │
│  │  - Zero copy buffer acquisition                                                  │  │
│  └───────────────────────────────────────────┬──────────────────────────────────────┘  │
│                                              │ put_nowait(raw_frame)                   │
│                                              ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Bounded Thread-Safe Ring Buffer Queue (maxsize = 10,000)                        │  │
│  └───────────────────────────────────────────┬──────────────────────────────────────┘  │
│                                              │ get(timeout=0.01)                       │
│                                              ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │  THREAD 2: Parser & Threat Evaluation Engine (Consumer)                          │  │
│  │  - Bitwise L2/L3/L4 Protocol Header Dissection                                   │  │
│  │  - Sliding Window Metric Updates (collections.deque per IP)                      │  │
│  │  - Heuristic Threat Rule Evaluators (Port Scan, DoS, ARP, Brute Force)           │  │
│  └─────────────────────┬────────────────────────────────────────┬───────────────────┘  │
│                        │ (Incident Dispatched)                  │ (Metrics / Packets)  │
│                        ▼                                        ▼                      │
│  ┌───────────────────────────────┐            ┌─────────────────────────────────────┐  │
│  │   MongoDB Persistence Pool    │            │  Async Event Loop (FastAPI/Node)    │  │
│  │  - Batch write operations     │            │  - Socket.io Real-Time Gateway      │  │
│  │  - 24h TTL Index Lifecycle    │            │  - REST API Routing & Auth          │  │
│  └───────────────────────────────┘            └──────────────────┬──────────────────┘  │
│                                                                  │ (WebSockets / WSS)  │
│                                                                  ▼                     │
│                                               ┌─────────────────────────────────────┐  │
│                                               │ React.js Client Dashboard UI (60fps)│  │
│                                               └─────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Low-Level Protocol Parsing & Bitwise Extraction

### 2.1 Bitwise Header Deconstruction Specifications

The parser reads raw byte slices directly from memory buffers to eliminate overhead.

#### 1. Ethernet II Header (14 Bytes)
$$\text{Offset } 0..5: \text{Destination MAC} \quad | \quad \text{Offset } 6..11: \text{Source MAC} \quad | \quad \text{Offset } 12..13: \text{EtherType}$$
- EtherType `0x0800` $\rightarrow$ IPv4
- EtherType `0x0806` $\rightarrow$ ARP
- EtherType `0x86DD` $\rightarrow$ IPv6

#### 2. IPv4 Header (Minimum 20 Bytes)
- **Version & IHL (Byte 0)**: `Version = (Byte[0] >> 4) & 0x0F`, `IHL = (Byte[0] & 0x0F) * 4 bytes`.
- **Total Length (Bytes 2–3)**: `(Byte[2] << 8) | Byte[3]`.
- **TTL (Byte 8)**: Integer value (e.g., 64, 128).
- **Protocol (Byte 9)**: `1` = ICMP, `6` = TCP, `17` = UDP.
- **Source IP (Bytes 12–15)**: `socket.inet_ntoa(Byte[12:16])`.
- **Destination IP (Bytes 16–19)**: `socket.inet_ntoa(Byte[16:20])`.

#### 3. TCP Header (Minimum 20 Bytes)
- **Source Port (Bytes 0–1)**: `(Byte[0] << 8) | Byte[1]`.
- **Destination Port (Bytes 2–3)**: `(Byte[2] << 8) | Byte[3]`.
- **Sequence Number (Bytes 4–7)**: 32-bit unsigned integer.
- **Acknowledgment Number (Bytes 8–11)**: 32-bit unsigned integer.
- **Data Offset (Byte 12)**: `(Byte[12] >> 4) * 4 bytes`.
- **TCP Control Flags (Byte 13)**:
  - `FIN = (Byte[13] & 0x01) != 0`
  - `SYN = (Byte[13] & 0x02) != 0`
  - `RST = (Byte[13] & 0x04) != 0`
  - `PSH = (Byte[13] & 0x08) != 0`
  - `ACK = (Byte[13] & 0x10) != 0`
  - `URG = (Byte[13] & 0x20) != 0`

---

## 3. High-Performance In-Memory Data Structures

### 3.1 Per-IP Sliding Window Queue Structure
To maintain $O(1)$ amortized insertion and eviction for sliding window heuristics:

```python
import collections
import time

class SlidingWindowState:
    def __init__(self, window_duration=5.0):
        self.window_duration = window_duration
        # Double-ended queue storing tuples: (timestamp, dst_port, flags)
        self.packet_history = collections.deque()
        self.port_frequencies = collections.defaultdict(int)

    def record_packet(self, timestamp, dst_port, flags):
        # 1. Enqueue new packet record
        self.packet_history.append((timestamp, dst_port, flags))
        self.port_frequencies[dst_port] += 1
        
        # 2. Evict expired entries older than (current_time - window_duration)
        cutoff = timestamp - self.window_duration
        while self.packet_history and self.packet_history[0][0] < cutoff:
            old_time, old_port, _ = self.packet_history.popleft()
            self.port_frequencies[old_port] -= 1
            if self.port_frequencies[old_port] <= 0:
                del self.port_frequencies[old_port]

    @property
    def distinct_ports_count(self):
        return len(self.port_frequencies)
```

---

## 4. Real-Time WebSocket Protocol Specification

All real-time communications utilize **RFC 6455 WebSockets** managed via `Socket.io`.

### 4.1 WebSocket Event Schema Catalog

#### Event: `packet:stream`
- **Emission Rate**: Throttled every $100\text{ ms}$ (contains batch array of packets).
- **Payload Schema**:
```json
[
  {
    "id": "pkt_10829",
    "timestamp": 1789421130120,
    "src": "192.168.1.150:48291",
    "dst": "192.168.1.1:80",
    "proto": "TCP",
    "len": 60,
    "flags": ["SYN"],
    "info": "Seq=108294 Win=64240"
  }
]
```

#### Event: `metrics:update`
- **Emission Rate**: Emitted every $1,000\text{ ms}$ (1 Second).
- **Payload Schema**:
```json
{
  "timestamp": 1789421130000,
  "throughput_mbps": 4.82,
  "packets_per_sec": 1240,
  "bytes_in": 524288,
  "bytes_out": 78643,
  "protocols": {
    "tcp_pct": 74.2,
    "udp_pct": 18.1,
    "icmp_pct": 4.9,
    "arp_pct": 2.8
  },
  "top_talkers": [
    { "ip": "192.168.1.150", "mbps": 3.4 },
    { "ip": "192.168.1.45", "mbps": 1.1 }
  ]
}
```

#### Event: `alert:new`
- **Emission Rate**: Instantaneous on threat detection ($< 10\text{ ms}$ internal dispatch latency).
- **Payload Schema**:
```json
{
  "alert_id": "alt_94812",
  "timestamp": "2026-09-13T15:25:31.000Z",
  "threat_type": "PORT_SCAN_DETECTED",
  "severity": "HIGH",
  "source_ip": "192.168.1.150",
  "target_ip": "192.168.1.1",
  "description": "Rapid port probe detected: 48 distinct ports probed in 3.2 seconds.",
  "mitigation": "iptables -A INPUT -s 192.168.1.150 -j DROP",
  "status": "NEW"
}
```

---

## 5. REST API Contract & Specifications

Base URL: `http://localhost:5000/api/v1`

### 5.1 Endpoints Table

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/system/status` | Current capture status, CPU/RAM, active NIC | Yes (Viewer/Admin) |
| `GET` | `/system/interfaces` | List all available OS network adapters | Yes (Admin) |
| `POST`| `/capture/start` | Start sniffing on specified interface | Yes (Admin) |
| `POST`| `/capture/stop` | Halt active capture | Yes (Admin) |
| `GET` | `/alerts` | Get paginated alert list with filters | Yes (Viewer/Admin) |
| `PATCH`| `/alerts/:id` | Update alert status (`ACKNOWLEDGED`/`RESOLVED`)| Yes (Analyst/Admin) |
| `GET` | `/devices` | Get discovered host inventory | Yes (Viewer/Admin) |
| `GET` | `/analytics/forensics`| Search historical packets & attack logs | Yes (Analyst/Admin) |
| `GET` | `/config/thresholds` | Fetch current threat detection parameters | Yes (Admin) |
| `PUT` | `/config/thresholds` | Update detection threshold parameters | Yes (Admin) |

---

## 6. Resilience, Fault Tolerance & Memory Safety

1. **Packet Dropping Circuit Breaker**: If raw queue depth reaches $> 9,500$ frames (95% of buffer capacity), the producer thread automatically drops non-TCP/UDP broadcast frames to protect critical threat detection queues.
2. **TTL Automated Pruning**: Raw packet documents expire automatically after 24 hours via MongoDB's background TTL index thread (`expireAfterSeconds: 86400`), preventing local disk exhaustion.
3. **Graceful Socket Recovery**: If the host network adapter undergoes an IP address change or temporary link-down state, the sniffer thread attempts reconnection every 2.0 seconds without crashing the web process.
