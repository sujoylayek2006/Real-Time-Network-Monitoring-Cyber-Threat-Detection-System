# UI/UX Design Specification Document (UI/UX D)
## Real-Time Network Monitoring and Threat Detection System
*(Web-Based Network Monitoring and Network Attack Analyzer)*

---

### Executive Overview
This document specifies the complete User Interface (UI) and User Experience (UX) design standards, wireframes, design tokens, component hierarchies, and interactive behavior for the **Real-Time Network Monitoring and Threat Detection System**. 

The interface is engineered specifically for **Network Administrators, Security Analysts, and Academic Evaluators**, delivering a modern, high-contrast, cyberpunk/SOC (Security Operations Center) dark-mode theme with glassmorphism visual elements, fluid real-time data streaming animations, and intuitive alert triage workflows.

---

## 1. Design Philosophy & Aesthetic Principles

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CORE DESIGN PRINCIPLES                          │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ 1. Zero Visual Lag│ 2. Rapid Triage   │ 3. SOC Dark Aesthetic          │
│ Sub-second live   │ Color-coded threat│ Sleek deep-slate background    │
│ updates without UI│ badges & instant  │ with vibrant neon accents &    │
│ stuttering/drops  │ remediation paths │ glassmorphism card containers  │
└───────────────────┴───────────────────┴────────────────────────────────┘
```

1. **Information Density with Clarity**: Dense telemetry (IP addresses, packet sizes, protocol flags) presented in clean, well-aligned tabular grids and modern chart widgets without visual clutter.
2. **High-Contrast Dark Theme**: Designed to prevent eye strain during continuous network monitoring while ensuring critical alerts (red/amber) stand out immediately.
3. **Sub-Second Perceived Performance**: Virtualized packet tables, optimistic UI state updates for alert acknowledgment, and smooth cubic-bezier chart transitions.
4. **Accessible Cyber Aesthetics**: Glassmorphic panels (`backdrop-filter: blur(12px)`), subtle neon borders, glowing status indicators, and clean typography.

---

## 2. Design System & Style Tokens

### 2.1 Color Palette & Tokens

```
┌────────────────────────────────────────────────────────────────────────┐
│                          COLOR TOKEN SYSTEM                            │
├─────────────────┬──────────────────┬─────────────────┬─────────────────┤
│ Background Deep │ Surface/Cards    │ Primary Accent  │ Threat Critical │
│ #0B0F19 (Slate) │ #111827 (Glass)  │ #3B82F6 (Blue)  │ #EF4444 (Red)   │
├─────────────────┼──────────────────┼─────────────────┼─────────────────┤
│ Threat High     │ Threat Medium    │ Success/Active  │ Text Primary    │
│ #F97316 (Orange)│ #EAB308 (Amber)  │ #10B981 (Emerald│ #F9FAFB (White) │
└─────────────────┴──────────────────┴─────────────────┴─────────────────┘
```

| Token Name | HEX Code | CSS Variable | Semantic Usage |
| :--- | :--- | :--- | :--- |
| `--bg-base` | `#0B0F19` | `var(--bg-base)` | App background base |
| `--bg-surface` | `#111827` (80% opacity) | `var(--bg-surface)` | Glassmorphism card surfaces & modals |
| `--border-subtle`| `#1F2937` | `var(--border-subtle)`| Card borders & table dividers |
| `--border-glow` | `#3B82F6` (30% opacity) | `var(--border-glow)` | Active card hover states & input focus |
| `--text-primary` | `#F9FAFB` | `var(--text-primary)` | Headings, main metrics, key text |
| `--text-muted` | `#9CA3AF` | `var(--text-muted)` | Labels, timestamps, secondary descriptions |
| `--accent-cyan` | `#06B6D4` | `var(--accent-cyan)` | Live streaming packet highlights |
| `--severity-critical`| `#EF4444` | `var(--severity-critical)`| SYN Flood, ARP Poisoning alerts |
| `--severity-high`| `#F97316` | `var(--severity-high)`| Port scan, Brute force alerts |
| `--severity-medium`| `#EAB308` | `var(--severity-medium)`| Stealth scan, Traffic spike alerts |
| `--severity-low` | `#3B82F6` | `var(--severity-low)` | Informational warnings, Ping bursts |
| `--status-active`| `#10B981` | `var(--status-active)`| Sniffer running, Host online |

### 2.2 Typography System
- **Primary Font Family**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `sans-serif` (Clean, highly legible UI typography).
- **Monospace Font Family**: `JetBrains Mono`, `Fira Code`, `SFMono-Regular`, `Consolas`, `monospace` (For IP addresses, MACs, hex dumps, ports, and packet flags).

| Style | Font Size | Line Height | Weight | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Display Heading** | `28px (1.75rem)` | `34px` | Bold (700) | Main page titles, High-level metrics |
| **Section Heading** | `20px (1.25rem)` | `28px` | SemiBold (600) | Card headers, Modal titles |
| **Subheading** | `15px (0.938rem)`| `22px` | Medium (500) | Widget sub-headers, Table group labels|
| **Body Regular** | `14px (0.875rem)`| `20px` | Regular (400) | General content, table cell values |
| **Code / Mono** | `13px (0.813rem)`| `18px` | Medium (500) | IPs, MACs, Ports, JSON payloads |
| **Caption / Badge** | `11px (0.688rem)`| `14px` | SemiBold (600) | Severity badges, status pills, tags |

### 2.3 Elevation, Shadows & Glassmorphism
```css
/* Core Glassmorphic Surface Token */
.glass-panel {
  background: rgba(17, 24, 39, 0.75);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  border-radius: 12px;
}

/* Glowing Border on Threat / Active Focus */
.glow-critical {
  border-color: rgba(239, 68, 68, 0.5);
  box-shadow: 0 0 15px rgba(239, 68, 68, 0.25);
}
```

---

## 3. Global App Layout & Navigation Hierarchy

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  [🛡️ NET-SENTINEL]  Interface: [eth0 (192.168.1.45) ▼]  [🟢 SNIFFING]  [🔔 3] [👤 Admin]│
├──────────────┬─────────────────────────────────────────────────────────────────────────┤
│ 📊 Dashboard │  [ Breadcrumbs: Network Monitor > Real-Time Dashboard ]                 │
│              ├─────────────────────────────────────────────────────────────────────────┤
│ ⚡ Live Packets│                                                                         │
│              │  ┌───────────────────────────────────────────────────────────────────┐  │
│ 🚨 Threat Hub│  │                        MAIN VIEWPORT                              │  │
│              │  │                                                                   │  │
│ 🖥️ Devices   │  │   (Rendered View: Dashboard / Packet Grid / Threat Center / etc.) │  │
│              │  │                                                                   │  │
│ 🔍 Forensics │  │                                                                   │  │
│              │  └───────────────────────────────────────────────────────────────────┘  │
│ ⚙️ Settings  │                                                                         │
├──────────────┴─────────────────────────────────────────────────────────────────────────┤
│  Status: Connected to ws://localhost:5000 | 12,450 pps | Buffer: 0.1% | MongoDB: Online │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Screen Layouts & Detailed Wireframes

### 4.1 View 1: Main Real-Time Operations Center (Dashboard)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ METRIC CARDS ROW                                                                       │
│ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐   │
│ │ TOTAL PACKETS    │ │ CURRENT SPEED    │ │ ACTIVE THREATS   │ │ CONNECTED HOSTS  │   │
│ │ 1,489,204        │ │ 4.82 Mbps        │ │ 3 CRITICAL       │ │ 18 Devices       │   │
│ │ ▲ +12.4% vs last │ │ ▲ 1,240 pkts/sec │ │ 🚨 Port Scan Act.│ │ 🟢 16 Online     │   │
│ └──────────────────┘ └──────────────────┘ └──────────────────┘ └──────────────────┘   │
├──────────────────────────────────────────┬─────────────────────────────────────────────┤
│ LIVE BANDWIDTH OVER TIME (Chart.js Line) │ PROTOCOL DISTRIBUTION (Donut Chart)         │
│ ┌──────────────────────────────────────┐ │ ┌─────────────────────────────────────────┐ │
│ │ 8M ┤       ┌─┐      ┌──┐             │ │ │             ████████                    │ │
│ │ 6M ┤   ┌───┘ └──┐  ┌┘  └──┐  (Ingress│ │ │          ███  TCP   ███    TCP: 74%     │ │
│ │ 4M ┤ ──┘        └──┘      └── Egress)│ │ │         ███   74%   ███   UDP: 18%     │ │
│ │ 2M ┤                                 │ │ │          ███       ███    ICMP: 5%     │ │
│ │ 0M ┴───┴───┴───┴───┴───┴───┴───┴───  │ │ │            ███████        ARP: 3%      │ │
│ │    15:20  15:21  15:22  15:23  15:24 │ │ └─────────────────────────────────────────┘ │
│ └──────────────────────────────────────┘ │                                             │
├──────────────────────────────────────────┴─────────────────────────────────────────────┤
│ RECENT REAL-TIME THREAT ALERTS (Quick Triage Feed)                        [View All ➔] │
│ ┌──────┬──────────────────────┬─────────────┬─────────────┬───────────┬──────────────┐     │
│ │ TIME │ THREAT TYPE          │ SOURCE IP   │ TARGET IP   │ SEVERITY  │ ACTION       │     │
│ ├──────┼──────────────────────┼─────────────┼─────────────┼───────────┼──────────────┤     │
│ │15:25 │ PORT_SCAN_DETECTED   │192.168.1.150│192.168.1.1  │ [🔴 HIGH] │ [Investigate]│     │
│ │15:24 │ SYN_FLOOD_DOS        │192.168.1.88 │192.168.1.45 │ [🚨 CRIT] │ [Investigate]│     │
│ │15:22 │ ARP_SPOOFING_ATTACK  │192.168.1.150│192.168.1.1  │ [🚨 CRIT] │ [Investigate]│     │
│ └──────┴──────────────────────┴─────────────┴─────────────┴───────────┴──────────────┘     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.2 View 2: Live Virtualized Packet Stream Table & Inspector Modal

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LIVE PACKET STREAM                        [⏸️ Pause] [▶️ Resume] [🗑️ Clear] [⚙️ Columns] │
│ Filter: [🔍 Search IP, Port, or Protocol...                               ] [Filter BPF]│
├──────────────┬──────────────────┬──────────────────┬──────────┬──────┬────────┬────────┤
│ TIMESTAMP    │ SOURCE IP:PORT   │ DEST IP:PORT     │ PROTOCOL │ LENGTH│ FLAGS  │ INFO   │
├──────────────┼──────────────────┼──────────────────┼──────────┼──────┼────────┼────────┤
│ 15:25:31.102 │ 192.168.1.150:482│ 192.168.1.1:80   │ TCP      │ 60 B │ [SYN]  │ Port 80│
│ 15:25:31.104 │ 192.168.1.150:483│ 192.168.1.1:443  │ TCP      │ 60 B │ [SYN]  │ Port443│
│ 15:25:31.106 │ 192.168.1.150:484│ 192.168.1.1:22   │ TCP      │ 60 B │ [SYN]  │ Port 22│
│ 15:25:31.120 │ 192.168.1.45:512 │ 8.8.8.8:53       │ UDP/DNS  │ 74 B │ ---    │ Q: google│
└──────────────┴──────────────────┴──────────────────┴──────────┴──────┴────────┴────────┘

┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🔍 MODAL: PACKET HEADER INSPECTOR (Triggered on Row Click)                 [✕ Close]   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ▾ Layer 2 (Ethernet II Frame)                                                          │
│   • Source MAC: 00:1A:2B:3C:4D:5E (Intel Corp) | Dest MAC: FF:FF:FF:FF:FF:FF (Bcast)   │
│ ▾ Layer 3 (IPv4 Header)                                                                │
│   • Source IP: 192.168.1.150 | Dest IP: 192.168.1.1 | TTL: 64 | Header Length: 20 B   │
│ ▾ Layer 4 (TCP Segment)                                                                │
│   • Source Port: 48291 | Dest Port: 80 (HTTP) | Seq: 1089204 | Ack: 0                  │
│   • Flags: [SYN] (0x02) | Window Size: 64240 | Checksum: 0x4f12 [Valid]              │
│ ▾ Raw Hex / ASCII Dump:                                                                │
│   0000  00 1a 2b 3c 4d 5e ff ff ff ff ff ff 08 00 45 00  ..+<M^........E.              │
│   0010  00 3c 1a 2b 40 00 40 06 7c 1a c0 a8 01 96 c0 a8  .<.+@.@.|.......              │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.3 View 3: Threat Center & Incident Resolution Hub

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🚨 THREAT CENTER & INCIDENT RESOLUTION HUB                   [🔊 Audio Alerts: ON]     │
│ Filter by Severity: [ All ] [🔴 Critical (2) ] [🟠 High (1) ] [🟡 Medium (0) ]          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 🚨 CRITICAL SEVERITY: SYN_FLOOD_DOS DETECTED                            [15:24:10] │ │
│ │ Attacker IP: 192.168.1.88  ──▶  Target IP: 192.168.1.45 (Workstation-04)           │ │
│ │ Heuristic Evidence: 840 SYN packets/sec with 0 ACK completions (Ratio: 42.0).     │ │
│ │                                                                                    │ │
│ │ 💡 Recommended Mitigation:                                                         │ │
│ │ `iptables -A INPUT -s 192.168.1.88 -j DROP` or enable OS SYN cookies.              │ │
│ │                                                                                    │ │
│ │ Actions: [ 🛡️ Copy Firewall Rule ] [ 👁️ View Attack Forensics ] [ ✅ Acknowledge ]│ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 🔴 HIGH SEVERITY: PORT_SCAN_DETECTED                                    [15:25:31] │ │
│ │ Attacker IP: 192.168.1.150 ──▶ Target IP: 192.168.1.1 (Gateway)                   │ │
│ │ Heuristic Evidence: Probed 48 distinct ports within 3.2 seconds window.            │ │
│ │ Scanned Ports: [21, 22, 23, 25, 80, 443, 3389, 8080, ...]                         │ │
│ │ Actions: [ 🛡️ Copy Firewall Rule ] [ 👁️ View Attack Forensics ] [ ✅ Acknowledge ]│ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.4 View 4: Connected Devices & Host Inventory Grid

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🖥️ CONNECTED NETWORK DEVICES (18 Active Hosts Discovered)       [🔍 Search Host / IP...]│
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ┌──────────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────────┐│
│ │ 🌐 192.168.1.1           │ │ 💻 192.168.1.45 (This PC)│ │ ⚠️ 192.168.1.150         ││
│ │ MAC: 00:50:56:C0:00:01   │ │ MAC: 00:1A:2B:3C:4D:5E   │ │ MAC: A4:C3:F0:89:12:34   ││
│ │ Host: gateway.router     │ │ Host: analyst-workstation│ │ Host: unknown-host.local ││
│ │ Vendor: Cisco Systems    │ │ Vendor: Intel Corporate  │ │ Vendor: Realtek Semicond ││
│ │ Tx: 48.2 MB | Rx: 92.4 MB│ │ Tx: 14.5 MB | Rx: 89.1 MB│ │ Tx: 184.2 MB | Rx: 1.2 MB││
│ │ Status: [🟢 ACTIVE]      │ │ Status: [🟢 ACTIVE]      │ │ Status: [🚨 THREAT HOST] ││
│ └──────────────────────────┘ └──────────────────────────┘ └──────────────────────────┘│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.5 View 5: Forensic Historical Log Query Engine

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🔍 FORENSIC INCIDENT LOGS & SEARCH ENGINE                                              │
│ [Date Range: 2026-09-01 to 2026-09-13 ▼] [Threat: All ▼] [Severity: All ▼] [IP: ___] │
│ [ 🔍 Run Query ] [ 📥 Export CSV ] [ 📥 Export JSON Report ]                           │
├──────────────┬──────────────────────┬─────────────┬─────────────┬──────────┬───────────┤
│ DATE/TIME    │ INCIDENT NAME        │ SOURCE IP   │ TARGET IP   │ SEVERITY │ STATUS    │
├──────────────┼──────────────────────┼─────────────┼─────────────┼──────────┼───────────┤
│ 2026-09-13   │ TCP SYN Flood Attack │192.168.1.88 │192.168.1.45 │ CRITICAL │ RESOLVED  │
│ 2026-09-13   │ TCP SYN Port Scan    │192.168.1.150│192.168.1.1  │ HIGH     │ ACKED     │
│ 2026-09-12   │ ARP Cache Poisoning  │192.168.1.150│192.168.1.1  │ CRITICAL │ RESOLVED  │
│ 2026-09-11   │ SSH Brute Force      │192.168.1.99 │192.168.1.45 │ HIGH     │ RESOLVED  │
└──────────────┴──────────────────────┴─────────────┴─────────────┴──────────┴───────────┘
```

---

### 4.6 View 6: System Settings & Threat Threshold Sliders

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ⚙️ SYSTEM SETTINGS & DETECTION TUNING                                                   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ▾ Capture Interface Settings:                                                          │
│   Active Network Interface: [ Wi-Fi Adapter (Intel Wi-Fi 6 AX201) - 192.168.1.45 ▼ ]    │
│   BPF Capture Filter:       [ ip or arp                                            ]    │
│   Promiscuous Mode:         [ (x) Enabled   ( ) Disabled                           ]    │
│                                                                                        │
│ ▾ Threat Detection Threshold Sliders:                                                  │
│   Port Scan Trigger (Distinct Ports in 5s): [─────●──────────] 20 Ports                │
│   SYN Flood Trigger (Packets / Second):     [──────────●─────] 100 PPS                 │
│   ICMP Flood Trigger (Packets / Second):    [─────●──────────] 50 PPS                  │
│   Brute Force Threshold (Attempts / Min):   [───●────────────] 15 Attempts             │
│                                                                                        │
│ ▾ Notification Preferences:                                                            │
│   [✓] Play Audio Chime on High/Critical Alerts                                         │
│   [✓] Browser Desktop Notifications                                                    │
│                                                                                        │
│ [ 💾 Save Configuration ] [ 🔄 Restore Defaults ]                                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Micro-Animations & Interactive Feedback States

1. **Pulsing Live Indicator**: The `[🟢 SNIFFING]` badge in the header pulses with a soft CSS keyframe glow (`scale(1.05)` and `box-shadow`) to provide reassuring visual proof that packets are actively flowing.
2. **Streaming Table Row Ingestion**: Incoming packet rows fade in with a 150ms subtle cyan tint before settling into the dark background.
3. **Alert Toast Slide-In**: High-priority alerts slide down from the top-right corner with a spring-physics ease curve and a synchronized audio chime.
4. **Optimistic Button Feedback**: Clicking "Acknowledge" instantly updates the alert status pill to a muted gray-green without waiting for server round-trip latency.

---

## 6. Accessibility & Responsive Breakpoints

- **Breakpoints**:
  - Desktop Ultra-Wide (1440p+): 4-column metrics, split chart-packet view.
  - Standard Desktop (1080p): 4-column metrics, stacked chart-packet view.
  - Laptop / Tablet (768px - 1024px): Collapsible sidebar, 2-column metrics.
- **Contrast Ratios**: All text tokens exceed **WCAG 2.1 AA** minimum contrast ratios of $4.5:1$ against dark background surfaces.
