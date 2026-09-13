# Security & Attack Detection Specifications
## Real-Time Network Monitoring and Threat Detection System

---

### Executive Overview
This document provides the formal mathematical, algorithmic, and heuristic specifications for the threat detection engine within the **Real-Time Network Monitoring and Threat Detection System**. The software operates passively on the host OS software network adapter, employing rule-based signatures, stateful connection tracking, and statistical sliding windows to detect malicious network vectors in real time.

---

## 1. Threat Taxonomy & Classification Matrix

| Threat Code | Attack Category | Severity | Detection Technique | Primary Protocol | Target Vulnerability |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PORT_SCAN_SYN` | Reconnaissance | **HIGH** | Sliding Window Distinct Port Counting | TCP (`SYN` Flag) | Service discovery / Port reconnaissance |
| `STEALTH_SCAN_XMAS` | Reconnaissance | **MEDIUM** | Binary Flag Signature (`FIN+PSH+URG`) | TCP (`0x29`) | Firewall evasion scan |
| `STEALTH_SCAN_NULL` | Reconnaissance | **MEDIUM** | Binary Flag Signature (`0x00`) | TCP (`No Flags`) | Firewall evasion scan |
| `SYN_FLOOD_DOS` | Denial of Service | **CRITICAL** | Half-Open Connection Ratio & PPS Threshold | TCP (`SYN` without `ACK`) | OS TCP connection backlog exhaustion |
| `ICMP_FLOOD_DOS` | Denial of Service | **HIGH** | Volumetric Rate Spike (pps) | ICMP (Echo Request) | Network bandwidth / CPU saturation |
| `UDP_FLOOD_DOS` | Denial of Service | **HIGH** | Volumetric Datagram Rate Threshold | UDP | Socket buffer starvation |
| `ARP_SPOOFING` | Man-In-The-Middle | **CRITICAL** | Dynamic IP-to-MAC Conflict Inspection | ARP (Opcode 2) | Layer 2 ARP cache poisoning & traffic interception |
| `BRUTE_FORCE_AUTH` | Credential Access | **HIGH** | Connection Reset & Frequency Analysis | TCP (Ports 22, 21, 3389, 80) | Password cracking / Authentication abuse |
| `TRAFFIC_SPIKE_ANOMALY` | Anomaly | **MEDIUM** | Statistical Z-Score Volumetric Deviation | All IP Protocols | Data exfiltration / Sudden botnet activity |

---

## 2. Mathematical Formulations & Detection Algorithms

### 2.1 Port Scan Detection (TCP SYN & UDP Sweeps)

#### Attack Mechanics
An attacker uses scanning tools (e.g., `nmap -sS`) to transmit probe packets to hundreds of consecutive TCP/UDP ports on a target host to identify open listening services.

#### Mathematical Model
Let $W_{src\_ip}(t, \Delta t)$ represent the sliding time window of duration $\Delta t$ (default: 5 seconds) for a given source IP address $src\_ip$. Let $P_{dst}(src\_ip, \Delta t)$ be the set of distinct destination ports probed within that window:

$$P_{dst}(src\_ip, \Delta t) = \left\{ dst\_port \mid \text{packet}(src\_ip, dst\_ip, dst\_port, \tau) \in W, \; \tau \in [t - \Delta t, t] \right\}$$

An alert of type `PORT_SCAN_DETECTED` is raised if:

$$|P_{dst}(src\_ip, \Delta t)| \ge \theta_{port\_scan} \quad (\text{Default Threshold: } \theta_{port\_scan} = 20 \text{ distinct ports})$$

#### Algorithm Pseudocode
```python
class PortScanDetector:
    def __init__(self, window_seconds=5.0, port_threshold=20):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        # Maps src_ip -> deque of (timestamp, dst_port)
        self.history = collections.defaultdict(collections.deque)

    def process_packet(self, packet):
        if not (packet.has_layer('TCP') or packet.has_layer('UDP')):
            return None
            
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        now = packet.timestamp
        
        queue = self.history[src_ip]
        queue.append((now, dst_port))
        
        # Purge entries older than the sliding window
        while queue and (now - queue[0][0]) > self.window_seconds:
            queue.popleft()
            
        # Calculate distinct destination ports
        distinct_ports = {port for _, port in queue}
        if len(distinct_ports) >= self.port_threshold:
            return Alert(
                threat_type="PORT_SCAN_DETECTED",
                severity="HIGH",
                source_ip=src_ip,
                target_ip=packet.dst_ip,
                details={"scanned_ports_count": len(distinct_ports), "window": self.window_seconds},
                mitigation="Block source IP via host firewall (e.g. iptables -A INPUT -s " + src_ip + " -j DROP)"
            )
        return None
```

---

### 2.2 Stealth Scan Detection (NULL & XMAS Scans)

#### Attack Mechanics
- **NULL Scan**: An attacker sends a TCP packet with all flag bits set to zero (`0x00`). According to RFC 793, closed ports respond with `RST`, while open ports drop the packet, allowing discovery without establishing a standard handshake.
- **XMAS Scan**: Transmits packets with `FIN` ($0x01$), `PSH` ($0x08$), and `URG` ($0x20$) flags simultaneously enabled ($0x29$ or $41$ in decimal), "lighting the packet up like a Christmas tree".

#### Algorithmic Signature Rule
```python
def check_stealth_scan(tcp_flags, src_ip, dst_ip, dst_port):
    # TCP flag masks: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32
    if tcp_flags == 0:
        return Alert(
            threat_type="STEALTH_SCAN_NULL",
            severity="MEDIUM",
            source_ip=src_ip,
            target_ip=dst_ip,
            details={"dst_port": dst_port, "flags": "0x00 (NULL)"},
            mitigation="Drop non-standard TCP flag combinations at OS network stack."
        )
    if tcp_flags == (0x01 | 0x08 | 0x20): # FIN + PSH + URG
        return Alert(
            threat_type="STEALTH_SCAN_XMAS",
            severity="MEDIUM",
            source_ip=src_ip,
            target_ip=dst_ip,
            details={"dst_port": dst_port, "flags": "0x29 (FIN+PSH+URG)"},
            mitigation="Configure firewall to reject TCP packets with invalid flag sets."
        )
    return None
```

---

### 2.3 Volumetric Denial of Service (TCP SYN Flood & ICMP Flood)

#### Attack Mechanics
- **SYN Flood**: Attacker transmits continuous TCP `SYN` packets from single or spoofed addresses without sending the terminating `ACK` to complete the 3-way handshake, exhausting the server's connection backlog table (`TCP half-open queue`).
- **ICMP / UDP Flood**: Overwhelms link capacity and CPU processing by transmitting high-frequency echo requests or UDP datagrams.

#### Mathematical Model
Let $N_{SYN}(src\_ip, \Delta t)$ be the number of SYN packets sent, and $N_{ACK}(src\_ip, \Delta t)$ be the number of ACK packets returned within $\Delta t = 1.0\text{s}$.

A `SYN_FLOOD_DOS` condition is triggered if either:
1. **Absolute Volumetric Rate**:
   $$\text{Rate}_{SYN}(src\_ip) = \frac{N_{SYN}(src\_ip, \Delta t)}{\Delta t} \ge \theta_{syn\_pps} \quad (\text{Default: } 100 \text{ pps})$$
2. **Half-Open Ratio**:
   $$\frac{N_{SYN}(src\_ip, \Delta t)}{N_{ACK}(src\_ip, \Delta t) + 1} \ge \theta_{ratio} \quad (\text{Default: } 10.0) \quad \text{and } N_{SYN} \ge 30$$

#### Algorithm Pseudocode
```python
class DoSFloodDetector:
    def __init__(self, syn_rate_threshold=100, icmp_rate_threshold=50):
        self.syn_rate_threshold = syn_rate_threshold
        self.icmp_rate_threshold = icmp_rate_threshold
        self.syn_counts = collections.defaultdict(int)
        self.icmp_counts = collections.defaultdict(int)
        self.last_reset = time.time()

    def tick(self, now):
        if now - self.last_reset >= 1.0:
            self.syn_counts.clear()
            self.icmp_counts.clear()
            self.last_reset = now

    def process_packet(self, packet):
        now = packet.timestamp
        self.tick(now)
        src_ip = packet.src_ip

        if packet.protocol == "TCP" and packet.tcp_flags.get("syn") and not packet.tcp_flags.get("ack"):
            self.syn_counts[src_ip] += 1
            if self.syn_counts[src_ip] >= self.syn_rate_threshold:
                return Alert(
                    threat_type="SYN_FLOOD_DOS",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    target_ip=packet.dst_ip,
                    details={"syn_rate_pps": self.syn_counts[src_ip]},
                    mitigation="Enable SYN cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) and rate-limit source IP."
                )

        elif packet.protocol == "ICMP" and packet.icmp_type == 8: # Echo Request
            self.icmp_counts[src_ip] += 1
            if self.icmp_counts[src_ip] >= self.icmp_rate_threshold:
                return Alert(
                    threat_type="ICMP_FLOOD_DOS",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=packet.dst_ip,
                    details={"icmp_rate_pps": self.icmp_counts[src_ip]},
                    mitigation="Rate-limit or filter ICMP Echo Requests at the software firewall."
                )
        return None
```

---

### 2.4 ARP Cache Poisoning / Spoofing Detection

#### Attack Mechanics
Address Resolution Protocol (ARP) lacks authentication. An attacker transmits fake gratuitous ARP replies associating their own MAC address with the IP address of the default gateway or another victim host, rerouting network traffic through the attacker's machine (Man-in-the-Middle).

#### Detection Mechanism
The system maintains a dynamic, authoritative state table of verified `(IP, MAC)` mappings:
1. When an `ARP Reply` (Opcode 2) is intercepted:
   - Check if `Sender IP` already exists in `Authoritative_Table`.
   - If `Sender IP` exists **AND** `Sender MAC` $\ne$ `Authoritative_Table[Sender IP]`:
     - Flag `ARP_SPOOFING_ATTACK`.

```python
class ARPSpoofDetector:
    def __init__(self):
        # Authoritative IP -> MAC binding map
        self.ip_mac_table = {}

    def process_arp(self, arp_packet):
        # Opcode 2 = ARP Reply / Is-At
        if arp_packet.opcode == 2:
            sender_ip = arp_packet.sender_ip
            sender_mac = arp_packet.sender_mac

            if sender_ip in self.ip_mac_table:
                known_mac = self.ip_mac_table[sender_ip]
                if known_mac.lower() != sender_mac.lower():
                    return Alert(
                        threat_type="ARP_SPOOFING_ATTACK",
                        severity="CRITICAL",
                        source_ip=sender_ip,
                        details={
                            "claimed_ip": sender_ip,
                            "attacker_mac": sender_mac,
                            "legitimate_mac": known_mac
                        },
                        mitigation="Immediate action required: Isolate MAC " + sender_mac + " and configure static ARP entries."
                    )
            else:
                # First time observed; register binding
                self.ip_mac_table[sender_ip] = sender_mac
        return None
```

---

### 2.5 Brute-Force Authentication Attempt Detection

#### Attack Mechanics
An attacker executes automated credential dictionary attacks against services listening on standard administrative ports (Port 22 SSH, Port 21 FTP, Port 3389 RDP, Port 80/443 Web Auth). Each failed attempt terminates with a rapid connection reset (`TCP RST`) or immediate teardown.

#### Heuristic Rule
- Track connection initiations (`SYN`) and quick teardowns (`RST`/`FIN`) targeted at sensitive port set $S_{auth} = \{21, 22, 23, 3389, 8080\}$.
- If connection frequency from a single source IP to $S_{auth}$ exceeds $\theta_{brute} = 15 \text{ attempts / minute}$, flag `BRUTE_FORCE_SUSPECTED`.

---

### 2.6 Statistical Traffic Spike Anomaly Detection (Z-Score)

#### Mathematical Model
Let $\mu$ and $\sigma$ represent the moving average and standard deviation of total bytes transferred per second over a 60-second baseline window:

$$\mu = \frac{1}{K} \sum_{i=1}^{K} x_i, \qquad \sigma = \sqrt{\frac{1}{K} \sum_{i=1}^{K} (x_i - \mu)^2}$$

For a newly observed 1-second throughput sample $x_t$, compute the Z-Score:

$$Z = \frac{x_t - \mu}{\sigma + \epsilon}$$

If $Z \ge 3.0$ (indicating traffic is 3 standard deviations above the moving baseline), trigger a `TRAFFIC_SPIKE_ANOMALY` notice.

---

## 3. False Positive Mitigation Strategies

To prevent legitimate high-throughput network applications (e.g. software downloads, video streaming, database migrations) from triggering false alarms:
1. **Configurable Whitelist / Allowlist**: Administrators can configure trusted IP ranges (e.g. DNS servers `8.8.8.8`, local gateway `192.168.1.1`) to bypass DoS/Port scan heuristics.
2. **Threshold Dampening & Cooldown Timers**: Once an alert is triggered for a specific `(Threat, Source IP)` tuple, an automatic 30-second cooldown suppression window activates to prevent flooding the alert feed with redundant duplicate notices.
3. **Multi-Factor Heuristic Verification**: Alerts require both rate and ratio thresholds to be satisfied before raising severity to `CRITICAL`.

---

## 4. Application & Dashboard Security Safeguards

1. **Packet Payload Sanitization**: Raw ASCII payload previews are sanitized using HTML entity encoding before rendering in the DOM, preventing Cross-Site Scripting (XSS) via injected packet payloads.
2. **JWT Authentication & Role Protection**: All modification API routes require valid signed JSON Web Tokens.
3. **NoSQL Injection Guard**: All database queries sanitize input parameters against operator injection (`$gt`, `$ne`, etc.).
