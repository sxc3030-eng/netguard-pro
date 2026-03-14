# 🛡️ NetGuard Pro

<div align="center">

![NetGuard Pro](https://img.shields.io/badge/NetGuard-Pro-4d9fff?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3dffb4?style=for-the-badge&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-3.0.0-ffb347?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-b47dff?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-11-0078d4?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-compatible-ff4d6a?style=for-the-badge&logo=linux&logoColor=white)

**Real-time network monitoring • Suricata IDS • Automatic blocking • WebSocket Dashboard**

[Quick Start](#-quick-start) • [Features](#-features) • [Installation](#-installation) • [API](#-rest-api-endpoints)

</div>

---

## ✨ Features

### Detection & Protection
| Feature | Description |
|---|---|
| **Port Scanning** | Detects port scans in real time (15+ ports / 10s) |
| **Brute Force** | Blocks SSH/RDP after 8 attempts / 30s |
| **SYN Flood** | DDoS protection |
| **DNS Tunneling** | Detects data exfiltration via DNS |
| **ARP Spoofing** | LAN attack protection |
| **Rate Limiting** | Dynamic progressive throttling → auto block |
| **Community Blacklist** | Auto-sync Spamhaus DROP + Blocklist.de (50k+ IPs) |

### Suricata IDS — 27 built-in rules
- Log4Shell, EternalBlue, WannaCry, Cobalt Strike, Mimikatz, AsyncRAT
- Emerging Threats — download 40,000+ community rules
- Every packet analyzed in real time

### Honeypot
- Fake SSH, FTP, Telnet, RDP, HTTP services on real ports
- Automatically identifies and blocks attackers on contact

### Real-time Dashboard
- Live updates every second via WebSocket
- Attacker countries pie chart with flags
- Top 10 suspicious IPs with risk scores
- World map with city-level dots (D3.js + zoom/pan)
- Multi-screen mode — detach any panel to a separate window

### Authentication & Multi-user (v3.0)
- Secure login with HTTPS support
- 3 roles: Admin / Operator (can block) / Viewer (read-only)
- PBKDF2-SHA256 password hashing, 8-hour sessions
- Full audit log of all user actions

### Alerts
- Email alerts (Gmail, Outlook, Yahoo) — HTML formatted
- Windows toast notifications
- Configurable severity threshold and cooldown

### REST API
```
GET /api/status     GET /api/state      GET /api/threats
GET /api/blocked    GET /api/history    GET /api/ip/<ip>
```

---

## 🔧 Installation

### Requirements
- Python 3.10+
- Windows: [Npcap](https://npcap.com/) for packet capture
- Linux: `sudo` for iptables

```bash
git clone https://github.com/sxc3030-eng/netguard-pro.git
cd netguard-pro
pip install scapy websockets
python netguard.py
```

**Default credentials:** `admin` / `netguard2024`

> Change your password immediately in the Users tab!

### Windows auto-start
```bat
install_service_windows.bat
```

### Linux systemd
```bash
sudo bash install_service_linux.sh
```

---

## 🚀 Quick Start

```bash
python netguard.py              # Normal mode
python netguard.py --no-block   # Monitor only
python netguard.py --api        # With REST API on :8766
python netguard.py --kiosk      # Full screen kiosk mode
```

Open `netguard_dashboard.html` in your browser — login, then connect.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                  NetGuard Pro v3.0                   │
├──────────────┬──────────────────┬────────────────────┤
│  Scapy       │  Python Engine   │  WebSocket :8765   │
│  Capture     │  IDS / DPI       │  Auth HTTP :8080   │
│              │  Suricata Rules  │  REST API  :8766   │
├──────────────┴──────────────────┴────────────────────┤
│              HTML / JS Dashboard                     │
│  Traffic • Threats • Map • Geo-block • Audit         │
└──────────────────────────────────────────────────────┘
```

**Stack:** Python 3.10+ • scapy • websockets • asyncio • D3.js • Chart.js

---

## 📁 Files

```
netguard.py                  Main Python backend
netguard_dashboard.html      Main dashboard
netguard_login.html          Login page
netguard_map.html            World map
netguard_panels.html         Multi-screen panels
netguard_history.html        Security reports
netguard_analyze.html        pcap/log analyzer
netguard_vitrine.html        Public landing page
netguard_tray.py             Windows system tray
build_windows.bat            Build .exe (PyInstaller)
netguard_installer.nsi       Full installer (NSIS)
```

---

## ⚠️ Legal

NetGuard Pro is for **monitoring your own network only**.
Do not use on networks without explicit authorization.
Requires administrator rights for firewall blocking.

---

## 📄 License

MIT License — Free, open source, modifiable.

---

## 👤 Author

**sxc3030-eng** — [github.com/sxc3030-eng/netguard-pro](https://github.com/sxc3030-eng/netguard-pro)

---

<div align="center">

⭐ **If NetGuard Pro is useful to you, please star it on GitHub!** ⭐

**[Download Latest Release](https://github.com/sxc3030-eng/netguard-pro/releases/latest)**

</div>
