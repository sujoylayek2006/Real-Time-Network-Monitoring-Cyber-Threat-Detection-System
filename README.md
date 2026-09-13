# Real-Time Network Monitoring and Threat Detection System
*(Web-Based Network Monitoring and Network Attack Analyzer)*

![Pure Software Solution](https://img.shields.io/badge/System-100%25%20Software%20Only-brightgreen)
![Standard](https://img.shields.io/badge/SRS%20Standard-IEEE%20830-blue)
![Architecture](https://img.shields.io/badge/Architecture-TAD%20%26%20Multi--Tier-purple)
![Database](https://img.shields.io/badge/Database-MongoDB%206.0+-green)
![Real-Time](https://img.shields.io/badge/Protocol-WebSockets%20%2F%20Socket.io-orange)

---

## 📌 Project Abstract
The **Real-Time Network Monitoring and Threat Detection System** (Net-Sentinel) is a full-stack, purely software-based network monitoring and cybersecurity attack analysis platform. Operating entirely on standard host operating system software network adapters (via `libpcap` / `Npcap` drivers), the system passively captures live network traffic, inspects multi-layer protocol headers, calculates real-time bandwidth and host statistics, and detects malicious cyber attack vectors in real time.

All telemetry—including live packet streams, bandwidth charts, connected device inventories, and critical threat alerts—is streamed with sub-second latency to an interactive, modern web dashboard.

---

## 📑 Complete Pre-Development Engineering Documentation Suite (14 Documents)

This repository contains the complete, industry-standard pre-development documentation suite required for engineering, product governance, academic thesis, and college project evaluation:

| # | Document Category | Document Title | Document Link |
| :-: | :--- | :--- | :--- |
| **01** | **Requirements** | **Software Requirements Specification (SRS)** (IEEE 830) | [📄 01_SRS_Document.md](file:///d:/Collage%20Project/docs/01_SRS_Document.md) |
| **02** | **Architecture** | **System Architecture & Data Flow Design** | [🏗️ 02_System_Architecture.md](file:///d:/Collage%20Project/docs/02_System_Architecture.md) |
| **03** | **Database** | **MongoDB Database Design & Data Architecture** | [🗄️ 03_MongoDB_Database_Design.md](file:///d:/Collage%20Project/docs/03_MongoDB_Database_Design.md) |
| **04** | **Visual Models** | **UML & Data Flow Diagrams (DFD Levels 0, 1, 2, ER)** | [📊 04_UML_and_DFD_Diagrams.md](file:///d:/Collage%20Project/docs/04_UML_and_DFD_Diagrams.md) |
| **05** | **Modules** | **System Module List & Technical Specifications** | [🖥️ 05_Module_List_and_Specifications.md](file:///d:/Collage%20Project/docs/05_Module_List_and_Specifications.md) |
| **06** | **Security** | **Security & Attack Detection Specifications** | [🔐 06_Security_and_Attack_Detection_Specifications.md](file:///d:/Collage%20Project/docs/06_Security_and_Attack_Detection_Specifications.md) |
| **07** | **Quality Assurance**| **Testing Documentation & QA Test Suite** | [🧪 07_Testing_Documentation.md](file:///d:/Collage%20Project/docs/07_Testing_Documentation.md) |
| **08** | **Project Plan** | **30-Day Development & Implementation Plan** | [📅 08_30_Day_Development_Plan.md](file:///d:/Collage%20Project/docs/08_30_Day_Development_Plan.md) |
| **09** | **Academic Report** | **Academic Final Project Report Structure (IEEE)** | [📑 09_Final_Project_Report_Structure.md](file:///d:/Collage%20Project/docs/09_Final_Project_Report_Structure.md) |
| **10** | **UI/UX Design** | **UI/UX Design Specification Document (UI/UX D)** | [🎨 10_UI_UX_Design_Specification.md](file:///d:/Collage%20Project/docs/10_UI_UX_Design_Specification.md) |
| **11** | **Product Specs** | **Product Requirements Document (PRD)** | [📋 11_PRD_Product_Requirements_Document.md](file:///d:/Collage%20Project/docs/11_PRD_Product_Requirements_Document.md) |
| **12** | **Tech Deep-Dive** | **Technical Architecture Document (TAD)** | [🏗️ 12_TAD_Technical_Architecture_Document.md](file:///d:/Collage%20Project/docs/12_TAD_Technical_Architecture_Document.md) |
| **13** | **Traceability** | **Functional Traceability Log & Matrix (FTL / RTM)** | [📊 13_FTL_Functional_Traceability_Log.md](file:///d:/Collage%20Project/docs/13_FTL_Functional_Traceability_Log.md) |
| **14** | **Folder Map** | **Project Folder Structure & Codebase Organization** | [📁 14_Project_Folder_Structure.md](file:///d:/Collage%20Project/docs/14_Project_Folder_Structure.md) |

---

## 🛡️ Attack Detection Capabilities

The system detects the following key network attack vectors using purely software-driven heuristic and signature analysis:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               ATTACK DETECTION MATRIX                                  │
├──────────────────────────┬─────────────────────────────┬──────────────┬────────────────┤
│ Attack Vector            │ Detection Mechanism         │ Severity     │ Protocol       │
├──────────────────────────┼─────────────────────────────┼──────────────┼────────────────┤
│ TCP SYN Port Scan        │ Sliding Window Port Count   │ HIGH         │ TCP (SYN)      │
│ TCP NULL Stealth Scan    │ Binary Flag Match (0x00)    │ MEDIUM       │ TCP (No flags) │
│ TCP XMAS Stealth Scan    │ Binary Flag Match (0x29)    │ MEDIUM       │ TCP (FIN/PSH/URG)│
│ Volumetric SYN Flood DoS │ Half-Open Connection Ratio  │ CRITICAL     │ TCP            │
│ ICMP Ping Flood DoS      │ Volumetric PPS Spike        │ HIGH         │ ICMP (Echo)    │
│ UDP Datagram Flood       │ Rate Threshold Evaluation   │ HIGH         │ UDP            │
│ ARP Cache Poisoning      │ IP-MAC Binding Conflict     │ CRITICAL     │ ARP (Opcode 2) │
│ Auth Brute Force Anomaly │ Rapid RST / Teardown Rate   │ HIGH         │ TCP (22/21/3389)│
│ Unusual Traffic Spike    │ Statistical Z-Score (3σ)    │ MEDIUM       │ All Protocols  │
└──────────────────────────┴─────────────────────────────┴──────────────┴────────────────┘
```

---

## 🏗️ High-Level Architectural Flow

```
   [ Local Network Traffic / Host Software Network Adapter ]
                              │
                              ▼
   ┌─────────────────────────────────────────────────────┐
   │             Passive Packet Sniffer Worker           │
   │           (Python Scapy / Libpcap Drivers)          │
   └──────────────────────────┬──────────────────────────┘
                              │ (Raw Binary Frames)
                              ▼
   ┌─────────────────────────────────────────────────────┐
   │          Protocol Dissector & Header Parser         │
   │         (Decodes L2 Ethernet, L3 IP, L4 TCP/UDP)    │
   └─────────────┬─────────────────────────┬─────────────┘
                 │                         │
                 ▼                         ▼
   ┌──────────────────────────┐ ┌────────────────────────┐
   │ Real-Time Threat Engine  │ │  Bandwidth Aggregator  │
   │ (Heuristics & Signatures)│ │  (Rolling Bps / pps)   │
   └─────────────┬────────────┘ └──────────┬─────────────┘
                 │ (Alerts)                │ (Metrics)
                 ├─────────────────────────┤
                 ▼                         ▼
   ┌──────────────────────────┐ ┌────────────────────────┐
   │   MongoDB Data Store     │ │   WebSocket Gateway    │
   │   (TTL Indexes & Logs)   │ │  (Sub-Second Broadcast)│
   └──────────────────────────┘ └──────────┬─────────────┘
                                           │
                                           ▼
   ┌─────────────────────────────────────────────────────┐
   │         Interactive Web Dashboard UI (React)        │
   │  - Live Bandwidth Chart     - Protocol Donut Chart  │
   │  - Live Packet Stream Grid  - Instant Alert Center  │
   │  - Active Device Explorer   - Forensic Log Search   │
   └─────────────────────────────────────────────────────┘
```

---

## 💻 Pure Software Technology Stack

- **Capture Engine & Worker**: Python 3.10+ / Scapy / `libpcap` / `Npcap` raw socket drivers.
- **Backend & Real-Time Server**: Python FastAPI / Node.js Express with `Socket.io` WebSockets.
- **Database Layer**: MongoDB 6.0+ with Mongoose / Motor, compound indexes, and 24h/30d TTL auto-expiration.
- **Frontend Dashboard**: React.js / Modern Web UI with Tailwind CSS, Chart.js / Recharts, and dark-mode glassmorphism styling.
- **Hardware Requirement**: **None** (100% Software Solution running on standard PC/laptop software network interfaces).
#   R e a l - T i m e - N e t w o r k - M o n i t o r i n g - C y b e r - T h r e a t - D e t e c t i o n - S y s t e m  
 