# MongoDB Database Design & Data Architecture
## Real-Time Network Monitoring and Threat Detection System

---

### Executive Summary
The data tier of the **Real-Time Network Monitoring and Threat Detection System** is implemented using **MongoDB**, a document-oriented NoSQL database. MongoDB was selected for its high write-throughput capabilities, flexible schemaless ingestion of varying network protocol attributes, rich aggregation framework, and built-in **Time-To-Live (TTL)** index support for automated data purging.

This document details the database architecture, JSON Schema validations, collection structures, indexing strategies, and aggregation pipelines.

---

## 1. Database Architecture & Design Strategies

### 1.1 Storage Strategy & Retention Policy
Network traffic produces high-velocity data streams. To ensure system performance and prevent storage exhaustion on standard host machines:
1. **Raw Packet Logs (`packet_logs`)**: Stored with an automatic **24-hour TTL index**. Old raw frames are automatically purged by MongoDB background workers.
2. **Aggregated Metrics (`bandwidth_metrics`)**: 1-minute metric buckets are retained for **30 days** using a TTL index.
3. **Security Incidents (`alerts` & `attack_logs`)**: Permanent persistence for forensic reporting, auditing, and college project evaluation demonstrations.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MongoDB Database: `network_monitor`             │
├──────────────────────────┬─────────────────────────┬───────────────────┤
│ Collection Name          │ Purpose                 │ Retention Policy  │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ `devices`                │ Connected host registry │ Permanent/Dynamic │
│ `packet_logs`            │ Raw packet headers      │ TTL: 24 Hours     │
│ `bandwidth_metrics`      │ Aggregated traffic stats│ TTL: 30 Days      │
│ `alerts`                 │ Threat detection alerts │ Permanent         │
│ `attack_logs`            │ Deep forensic evidence  │ Permanent         │
│ `users`                  │ Admin credentials/RBAC  │ Permanent         │
│ `system_settings`        │ Configurable thresholds │ Permanent (Single)│
└──────────────────────────┴─────────────────────────┴───────────────────┘
```

---

## 2. Collection Schemas & Data Models

### 2.1 Collection: `devices`
Tracks all discovered network hosts based on observed IP and MAC traffic.

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d1" },
  "mac_address": "00:1A:2B:3C:4D:5E",
  "ip_address": "192.168.1.45",
  "hostname": "workstation-04.local",
  "vendor": "Intel Corporate",
  "first_seen": { "$date": "2026-09-13T10:00:00.000Z" },
  "last_seen": { "$date": "2026-09-13T15:25:30.000Z" },
  "total_bytes_sent": 14589200,
  "total_bytes_received": 98452300,
  "total_packets": 84210,
  "status": "ACTIVE",
  "is_flagged_threat": false,
  "known_ports": [80, 443, 22]
}
```

#### JSON Schema Validation
```javascript
db.createCollection("devices", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["mac_address", "ip_address", "first_seen", "last_seen", "status"],
      properties: {
        mac_address: {
          bsonType: "string",
          pattern: "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
          description: "Must be a valid MAC address format."
        },
        ip_address: {
          bsonType: "string",
          description: "IPv4 or IPv6 string."
        },
        status: {
          enum: ["ACTIVE", "IDLE", "BLOCKED"],
          description: "Host operational status."
        },
        total_bytes_sent: { bsonType: "long" },
        total_bytes_received: { bsonType: "long" }
      }
    }
  }
});
```

---

### 2.2 Collection: `packet_logs`
Stores captured packet headers and basic protocol metadata. (Contains a 24-hour TTL).

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d2" },
  "timestamp": { "$date": "2026-09-13T15:25:30.120Z" },
  "interface": "eth0",
  "layer2": {
    "src_mac": "00:1A:2B:3C:4D:5E",
    "dst_mac": "FF:FF:FF:FF:FF:FF",
    "ethertype": "IPv4"
  },
  "layer3": {
    "src_ip": "192.168.1.45",
    "dst_ip": "192.168.1.1",
    "protocol": "TCP",
    "ttl": 64,
    "total_length": 60
  },
  "layer4": {
    "src_port": 54321,
    "dst_port": 80,
    "tcp_flags": {
      "syn": true,
      "ack": false,
      "fin": false,
      "rst": false,
      "psh": false,
      "urg": false
    },
    "seq_number": 34891204,
    "ack_number": 0
  },
  "payload_size_bytes": 0,
  "is_anomaly": false
}
```

---

### 2.3 Collection: `bandwidth_metrics`
Stores aggregated 1-minute telemetry rollups for charting throughput and protocol distributions.

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d3" },
  "timestamp": { "$date": "2026-09-13T15:25:00.000Z" },
  "duration_seconds": 60,
  "total_bytes": 5242880,
  "total_packets": 6400,
  "bytes_in": 4194304,
  "bytes_out": 1048576,
  "avg_mbps": 0.699,
  "peak_mbps": 2.45,
  "protocol_breakdown": {
    "tcp_bytes": 4404019,
    "udp_bytes": 734003,
    "icmp_bytes": 104858,
    "arp_bytes": 0
  },
  "top_talker_ips": [
    { "ip": "192.168.1.45", "bytes": 3145728 },
    { "ip": "192.168.1.102", "bytes": 1572864 }
  ]
}
```

---

### 2.4 Collection: `alerts`
Stores real-time threat detection alerts pushed to the administrator dashboard.

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d4" },
  "timestamp": { "$date": "2026-09-13T15:25:31.000Z" },
  "threat_type": "PORT_SCAN_DETECTED",
  "category": "RECONNAISSANCE",
  "severity": "HIGH",
  "source_ip": "192.168.1.150",
  "source_mac": "A4:C3:F0:89:12:34",
  "target_ip": "192.168.1.1",
  "description": "Rapid port probe detected: 48 distinct ports probed in 3.2 seconds.",
  "heuristic_details": {
    "ports_scanned_count": 48,
    "ports_sample": [21, 22, 23, 25, 80, 443, 3389, 8080],
    "time_window_seconds": 3.2,
    "scan_type": "TCP SYN SCAN"
  },
  "status": "NEW",
  "mitigation_recommendation": "Block Source IP 192.168.1.150 via firewall rule and inspect host endpoint for unauthorized network scanning tools.",
  "acknowledged_by": null,
  "resolved_at": null
}
```

#### JSON Schema Validation
```javascript
db.createCollection("alerts", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["timestamp", "threat_type", "severity", "source_ip", "status"],
      properties: {
        severity: {
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Alert severity level."
        },
        status: {
          enum: ["NEW", "ACKNOWLEDGED", "RESOLVED", "IGNORED"],
          description: "Workflow status of the incident."
        },
        threat_type: {
          enum: [
            "PORT_SCAN_DETECTED",
            "STEALTH_SCAN_XMAS",
            "STEALTH_SCAN_NULL",
            "SYN_FLOOD_DOS",
            "ICMP_FLOOD_DOS",
            "UDP_FLOOD_DOS",
            "ARP_SPOOFING_ATTACK",
            "BRUTE_FORCE_SUSPECTED",
            "UNUSUAL_TRAFFIC_SPIKE"
          ]
        }
      }
    }
  }
});
```

---

### 2.5 Collection: `attack_logs`
Stores detailed forensic records for deep attack analysis and evidence presentation.

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d5" },
  "alert_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d4" },
  "timestamp": { "$date": "2026-09-13T15:25:31.000Z" },
  "attack_name": "TCP SYN Flood Attack",
  "attacker_ip": "192.168.1.150",
  "attacker_mac": "A4:C3:F0:89:12:34",
  "victim_ip": "192.168.1.1",
  "target_port": 80,
  "packet_sample": [
    {
      "timestamp": "15:25:30.100",
      "flags": "SYN",
      "seq": 1029384,
      "length": 54
    },
    {
      "timestamp": "15:25:30.105",
      "flags": "SYN",
      "seq": 1029385,
      "length": 54
    }
  ],
  "metrics_at_attack": {
    "packets_per_sec": 845,
    "syn_ack_ratio": 42.5
  },
  "forensic_notes": "Attacker generated continuous SYN requests without responding to SYN-ACK, exhausting connection pool."
}
```

---

### 2.6 Collection: `users`
Stores system administrators and security analyst accounts with Role-Based Access Control (RBAC).

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d6" },
  "username": "admin",
  "email": "admin@network.local",
  "password_hash": "$2a$12$e8Ym...hashed_bcrypt_secret",
  "role": "SUPER_ADMIN",
  "created_at": { "$date": "2026-09-01T00:00:00.000Z" },
  "last_login": { "$date": "2026-09-13T14:30:00.000Z" },
  "is_active": true
}
```

---

### 2.7 Collection: `system_settings`
Stores dynamic runtime thresholds for threat detection rules.

```json
{
  "_id": { "$oid": "64f1a2b3c4d5e6f7a8b9c0d7" },
  "selected_interface": "eth0",
  "bpf_filter": "ip or arp",
  "thresholds": {
    "port_scan_distinct_ports": 20,
    "port_scan_window_seconds": 5,
    "syn_flood_pps": 100,
    "syn_ack_ratio_threshold": 10,
    "icmp_flood_pps": 50,
    "brute_force_failed_attempts": 15,
    "brute_force_window_seconds": 60
  },
  "alert_notifications": {
    "audio_enabled": true,
    "popup_enabled": true
  },
  "retention_days": {
    "raw_packets": 1,
    "metrics": 30
  }
}
```

---

## 3. Indexing Strategy

To guarantee sub-millisecond query performance across large packet volumes, the following indexes are defined:

```javascript
// 1. Packet Logs: TTL index for 24-hour auto-purge + Compound filter index
db.packet_logs.createIndex({ "timestamp": 1 }, { expireAfterSeconds: 86400 });
db.packet_logs.createIndex({ "layer3.src_ip": 1, "timestamp": -1 });
db.packet_logs.createIndex({ "layer3.protocol": 1, "timestamp": -1 });

// 2. Devices: Unique MAC and fast IP lookup
db.devices.createIndex({ "mac_address": 1 }, { unique: true });
db.devices.createIndex({ "ip_address": 1 });
db.devices.createIndex({ "status": 1, "last_seen": -1 });

// 3. Alerts: Filter by status, severity, and timestamp
db.alerts.createIndex({ "status": 1, "severity": 1, "timestamp": -1 });
db.alerts.createIndex({ "source_ip": 1, "timestamp": -1 });
db.alerts.createIndex({ "threat_type": 1 });

// 4. Attack Logs: Linked to alert and attacker
db.attack_logs.createIndex({ "alert_id": 1 });
db.attack_logs.createIndex({ "attacker_ip": 1, "timestamp": -1 });

// 5. Bandwidth Metrics: TTL index for 30 days + Time range index
db.bandwidth_metrics.createIndex({ "timestamp": 1 }, { expireAfterSeconds: 2592000 });
```

---

## 4. Analytical MongoDB Aggregation Pipelines

### 4.1 Top 5 Bandwidth Consuming IPs (Last 1 Hour)
```javascript
db.packet_logs.aggregate([
  {
    $match: {
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
    }
  },
  {
    $group: {
      _id: "$layer3.src_ip",
      totalBytes: { $sum: "$layer3.total_length" },
      packetCount: { $sum: 1 }
    }
  },
  { $sort: { totalBytes: -1 } },
  { $limit: 5 },
  {
    $project: {
      ip_address: "$_id",
      totalBytes: 1,
      packetCount: 1,
      _id: 0
    }
  }
]);
```

### 4.2 Threat Frequency by Category (Dashboard Radar Chart)
```javascript
db.alerts.aggregate([
  {
    $group: {
      _id: "$threat_type",
      count: { $sum: 1 },
      lastOccurrence: { $max: "$timestamp" }
    }
  },
  { $sort: { count: -1 } }
]);
```
