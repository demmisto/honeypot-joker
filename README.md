<div align="center">

```
██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  █████╗ ██████╗ 
██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝    ██║   ██████╔╝███████║██████╔╝
██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝     ██║   ██╔══██╗██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
```

**A full-featured Python honeypot that looks real to nmap.**  
6 protocols · Live web GUI · WebSocket event streaming · Credential capture · Log export

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3%2B-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-6-orange?style=flat-square)](#-protocol-emulators)

</div>

---

> ⚠️ **For authorized security research, lab environments, and educational use only.**  
> Deploy only on networks you own or have explicit written permission to monitor.

---

## What is HoneyTrap?

HoneyTrap is a **Python-based honeypot framework** that spins up emulated services for SSH, FTP, HTTP, Telnet, SNMP, and SMB — each producing **real protocol handshakes** that make them indistinguishable from legitimate services on an nmap version scan (`-sV`).

A dark-themed web GUI streams all attacker activity in real time via WebSockets, captures credentials, detects suspicious payloads, and lets you download structured daily logs per protocol.

---

## Features

```
┌─────────────────────────────────────────────────────────────────┐
│  PROTOCOL EMULATORS                                             │
│  ├── SSH     — Real RSA handshake via paramiko                  │
│  ├── FTP     — Banner + full command loop (USER/PASS/SYST/FEAT) │
│  ├── HTTP    — HTTP/1.1 responses, exploit path detection       │
│  ├── Telnet  — IAC negotiation bytes + credential capture       │
│  ├── SNMP    — UDP agent, responds to GET (noSuchName)          │
│  └── SMB     — SMBv1 Negotiate Protocol Response                │
│                                                                 │
│  WEB DASHBOARD                                                  │
│  ├── Overview    — Live stat cards per protocol                 │
│  ├── Live Feed   — WebSocket event stream, filterable           │
│  ├── Control     — Start/stop services, configure ports/banners │
│  └── Log Viewer  — Browse & download daily per-protocol logs    │
│                                                                 │
│  DETECTION                                                      │
│  ├── Credential capture (username + password on every attempt)  │
│  ├── HTTP exploit path detection (/../ /etc/passwd SQLi XSS…)   │
│  ├── SMB v1/v2/v3 command logging                               │
│  ├── SNMP community string logging                              │
│  └── Severity tagging: INFO / ALERT / CRITICAL                  │
│                                                                 │
│  OPERATIONS                                                      │
│  ├── Predefined CVE-mapped vulnerable banners per protocol      │
│  ├── Custom banner strings                                       │
│  ├── Per-protocol + combined daily log files                    │
│  ├── Log download from GUI                                      │
│  └── First-run setup wizard (no config file editing)           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip
- Windows (Linux/macOS also works — use `python honeypot.py` directly)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourname/honeytrap.git
cd honeytrap

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch
python honeypot.py
```

**Windows shortcut:** double-click `start.bat` — it installs dependencies and launches automatically.

### First-Run Setup Wizard

On first launch you will be prompted to set credentials:

```
═══════════════════════════════════════════════════════
   🍯  HoneyTrap - Honeypot Framework  🍯
═══════════════════════════════════════════════════════

First-time setup — configure GUI credentials

  GUI Username: admin
  GUI Password: ········
  Confirm Password: ········
  GUI Port [8080]: 

  ✓ Config saved. GUI will start at http://localhost:8080
```

Then open **http://localhost:8080** in your browser.

---

## Project Structure

```
honeytrap/
├── honeypot.py              ← Main application (all protocol servers + Flask app)
├── requirements.txt         ← Python dependencies
├── start.bat                ← Windows one-click launcher
├── honeypot_config.json     ← Generated on first run (credentials + port config)
├── ssh_host_key             ← Generated RSA key for SSH emulator
├── templates/
│   ├── login.html           ← Authentication page
│   └── dashboard.html       ← Full web GUI (WebSocket-driven)
└── logs/
    ├── combined_YYYY-MM-DD.log
    ├── ssh_YYYY-MM-DD.log
    ├── ftp_YYYY-MM-DD.log
    ├── http_YYYY-MM-DD.log
    ├── telnet_YYYY-MM-DD.log
    ├── snmp_YYYY-MM-DD.log
    └── smb_YYYY-MM-DD.log
```

---

## Protocol Emulators

| Protocol | Default Port | Transport | nmap `-sV` result |
|----------|:-----------:|:---------:|-------------------|
| SSH      | 2222        | TCP       | Detects exact OpenSSH/Dropbear version from banner + RSA handshake |
| FTP      | 2121        | TCP       | Detects vsFTPd / ProFTPD / FileZilla version |
| HTTP     | 8888        | TCP       | Detects Apache / IIS / nginx from `Server:` header |
| Telnet   | 2323        | TCP       | Identifies as Telnet service via IAC bytes |
| SNMP     | 1161        | **UDP**   | Detected as SNMP agent (responds to GET with noSuchName) |
| SMB      | 4450        | TCP       | Fingerprinted as Windows / Samba via SMBv1 negotiate response |

> **Standard ports** (22, 21, 80, 23, 161, 445) require running as **Administrator** on Windows. Change ports in the GUI Control tab after launch.

---

## Predefined Vulnerable Banners

Each protocol ships with CVE-mapped banners you can select from a dropdown in the GUI.

### 🔐 SSH

| Banner | CVE | Description |
|--------|-----|-------------|
| `SSH-2.0-OpenSSH_7.4` | CVE-2017-15906 | Unauthorized write via sftp |
| `SSH-2.0-OpenSSH_6.6` | Multiple | Auth bypass / info disclosure |
| `SSH-2.0-dropbear_2016.74` | — | Old embedded router firmware |
| `SSH-2.0-OpenSSH_5.3` | CVE-2010-5107 | RHEL 6 legacy |

### 📂 FTP

| Banner | CVE | Description |
|--------|-----|-------------|
| `220 (vsFTPd 2.3.4)` | **CVE-2011-2523** | Famous backdoor on port 6200 |
| `220 ProFTPD 1.3.3c Server` | **CVE-2010-4221** | Stack-based buffer overflow |
| `220-FileZilla Server version 0.9.41 beta` | — | Old FileZilla Windows server |
| `220 Microsoft FTP Service` | — | Windows IIS FTP |

### 🌐 HTTP

| Banner | CVE | Description |
|--------|-----|-------------|
| `Apache/2.2.8 (Ubuntu)` | CVE-2017-7679 | mod_mime buffer overread |
| `Microsoft-IIS/6.0` | **CVE-2017-7269** | WebDAV buffer overflow (widely exploited) |
| `nginx/1.12.0` | CVE-2017-7529 | Integer overflow |
| `lighttpd/1.4.35` | CVE-2014-2323 | SQL injection in mod_mysql_vhost |

### 💬 Telnet

| Banner | Notes |
|--------|-------|
| `BusyBox v1.26.2` | Embedded Linux (routers, IoT) |
| `Cisco IOS 12.4` | Classic Cisco banner |
| `Debian GNU/Linux 8` | Generic Linux login |
| `MikroTik v6.40.5` | RouterOS banner |

### 🪟 SMB

| Banner | CVE | Description |
|--------|-----|-------------|
| `Windows XP Service Pack 3` | **MS17-010** | EternalBlue — most targeted banner |
| `Windows Server 2003` | MS17-010 | Server variant |
| `Samba 3.5.0-Debian` | **CVE-2017-7494** | SambaCry RCE |
| `Windows 7 Ultimate SP1` | MS17-010 | Common workstation target |

### 📡 SNMP

| Banner | Notes |
|--------|-------|
| `Linux honeypot 3.16.0` | Generic Linux agent |
| `Cisco Internetwork Operating System` | Cisco device |
| `Hardware: x86 - Software: Windows Version 5.2` | Windows SNMP |

---

## nmap Verification

Use these commands to confirm your honeypot looks legitimate:

```bash
# Version detection on all TCP honeypot ports
nmap -sV -p 2121,2222,2323,4450,8888 <honeypot-ip>

# UDP scan for SNMP
nmap -sU -p 1161 <honeypot-ip>

# Aggressive scan (triggers HTTP exploit detection, SMB fingerprinting)
nmap -A -p 2121,2222,2323,4450,8888 <honeypot-ip>

# Banner grab with netcat
nc <honeypot-ip> 2121      # FTP banner
nc <honeypot-ip> 8888      # HTTP (send: GET / HTTP/1.0\r\n\r\n)

# SMB version probe
nmap --script smb-os-discovery -p 4450 <honeypot-ip>
```

**Example nmap output against HoneyTrap:**

```
PORT     STATE SERVICE     VERSION
2121/tcp open  ftp         vsftpd 2.3.4
2222/tcp open  ssh         OpenSSH 7.4 (protocol 2.0)
2323/tcp open  telnet      Linux telnetd
4450/tcp open  microsoft-ds Microsoft Windows XP microsoft-ds
8888/tcp open  http        Apache httpd 2.2.8 ((Ubuntu))
```

---

## Web GUI

### Login Page
Authenticate with credentials set during first-run wizard. Session-based auth — only one active session.

### Overview Tab
- Per-protocol stat cards showing **total connections**, **alert count**, **port**, and live/offline status
- Recent events table (last 30)
- Recent alerts panel

### Live Feed Tab
Real-time WebSocket stream of all honeypot events.

- **Filter by protocol** — SSH / FTP / HTTP / Telnet / SNMP / SMB
- **Filter by severity** — INFO / ALERT / CRITICAL
- **Search** — filter by source IP or any text in the details field
- **Pause / Resume** — freeze the stream without losing events
- **Alert sidebar** — ALERT and CRITICAL events shown separately in real time

### Protocol Control Tab
Per-protocol configuration panel:

- **Start / Stop** toggle
- **Port** — change to any port (restart applies immediately)
- **Banner** — dropdown of predefined CVE-mapped banners, or enter a custom string
- **Save Config** — persists to `honeypot_config.json`, auto-restarts if service was running

### Log Viewer Tab
- Select protocol + date
- Colour-coded output: ALERT events in amber, AUTH_ATTEMPT / SUSPICIOUS in red
- **Download** button — exports the raw `.log` file
- Refresh button for live monitoring

---

## Log Format

```
[2024-01-15T14:32:11.004] [ALERT]    [SSH]    192.168.1.50:54321 | AUTH_ATTEMPT  | username=root password=toor
[2024-01-15T14:32:12.881] [INFO]     [FTP]    10.0.0.5:44123     | USER          | username=admin
[2024-01-15T14:32:13.002] [ALERT]    [FTP]    10.0.0.5:44123     | AUTH_ATTEMPT  | username=admin password=admin123
[2024-01-15T14:32:14.114] [ALERT]    [HTTP]   172.16.0.8:51200   | SUSPICIOUS_REQUEST | path=/etc/passwd possible exploit/scan
[2024-01-15T14:32:15.773] [INFO]     [SNMP]   10.0.0.100:34521   | SNMP_REQUEST  | community=public len=47
[2024-01-15T14:32:16.002] [ALERT]    [SNMP]   10.0.0.100:34521   | SNMP_REQUEST  | community=private len=47
[2024-01-15T14:32:18.551] [ALERT]    [SMB]    192.168.1.77:49201 | SMB_COMMAND   | SMBv1 command=0x72
[2024-01-15T14:32:19.002] [ALERT]    [TELNET] 10.10.10.5:58112   | AUTH_ATTEMPT  | username=admin password=admin
```

**Severity levels:**

| Level | Trigger |
|-------|---------|
| `INFO` | Connections, service events, benign commands |
| `ALERT` | Credential attempts, SNMP community strings, SMB probes, HTTP path scans |
| `CRITICAL` | Server errors, configuration failures |

---

## Configuration File

`honeypot_config.json` is auto-generated on first run. You can edit it manually if needed:

```json
{
  "gui_username": "admin",
  "gui_password_hash": "<sha256>",
  "gui_port": 8080,
  "protocols": {
    "ssh":    { "enabled": false, "port": 2222, "banner": "SSH-2.0-OpenSSH_7.4" },
    "ftp":    { "enabled": false, "port": 2121, "banner": "220 (vsFTPd 2.3.4)" },
    "http":   { "enabled": false, "port": 8888, "banner": "Apache/2.2.8 (Ubuntu)" },
    "telnet": { "enabled": false, "port": 2323, "banner": "\r\nlogin: " },
    "snmp":   { "enabled": false, "port": 1161, "banner": "NET-SNMP version 5.5" },
    "smb":    { "enabled": false, "port": 4450, "banner": "Windows XP Service Pack 3" }
  }
}
```

Set `"enabled": true` for any protocol to **auto-start it on next launch**.

---

## Using Standard Ports (22, 21, 80…)

To make HoneyTrap respond on the same ports as real services:

**Windows — run as Administrator:**
```bat
# Right-click start.bat → "Run as Administrator"
# Or from an elevated terminal:
python honeypot.py
```

Then in the GUI → **Protocol Control** → change the port for each service → **Save Config**.

**Port reference:**

| Protocol | Real Port | HoneyTrap Default |
|----------|:---------:|:-----------------:|
| SSH      | 22        | 2222              |
| FTP      | 21        | 2121              |
| HTTP     | 80        | 8888              |
| Telnet   | 23        | 2323              |
| SNMP     | 161 UDP   | 1161              |
| SMB      | 445       | 4450              |

---

## Extending — Adding a New Protocol

```python
# In honeypot.py

def run_myproto_server(port, banner, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    sock.settimeout(1.0)
    log_event("myproto", "0.0.0.0", port, "SERVER_START", f"Listening on {port}", "INFO")

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            src_ip, src_port = addr
            log_event("myproto", src_ip, src_port, "CONNECTION", "New connection", "INFO")
            # ... handle connection
            conn.close()
        except socket.timeout:
            continue

    sock.close()

# Register it
SERVER_FUNCTIONS["myproto"] = run_myproto_server

# Add to DEFAULT_CONFIG["protocols"]
DEFAULT_CONFIG["protocols"]["myproto"] = {
    "enabled": False, "port": 9999, "banner": "MyProto/1.0"
}

# Add predefined banners
DEFAULT_BANNERS["myproto"] = [
    {"name": "Version 1.0 (vulnerable)", "value": "MyProto/1.0"},
]
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `flask` | ≥ 2.3 | Web GUI server |
| `flask-socketio` | ≥ 5.3 | WebSocket event streaming |
| `paramiko` | ≥ 3.4 | Real SSH handshake emulation |
| `eventlet` | ≥ 0.35 | Async backend for SocketIO |

Install all with:
```bash
pip install -r requirements.txt
```

---

## Troubleshooting

**`Address already in use` on startup**  
Another service is on that port. Change the port in the GUI or kill the conflicting process:
```powershell
netstat -ano | findstr :<port>
taskkill /PID <pid> /F
```

**SSH not showing in nmap `-sV`**  
The `paramiko` library must be installed. Check:
```bash
pip show paramiko
```

**SNMP not responding**  
SNMP runs on UDP. Use nmap's UDP scan:
```bash
nmap -sU -p 1161 <ip>
```
UDP scans require Administrator/root on most systems.

**GUI not loading**  
Confirm the port isn't blocked by Windows Firewall:
```powershell
netsh advfirewall firewall add rule name="HoneyTrap GUI" dir=in action=allow protocol=TCP localport=8080
```

**`eventlet` import warning**  
If you see SSL monkey-patching warnings, they're harmless. HoneyTrap uses `threading` mode as fallback.

---

## Legal Notice

This tool is intended for:
- Security researchers studying attacker behavior
- Blue team training and lab environments  
- Authorized red team infrastructure simulation
- Educational demonstrations

**Do not** deploy this on production networks without explicit authorization. Capturing credentials from real users without consent may violate the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent laws in your jurisdiction.

---

<div align="center">

Built for the security community. Use responsibly.

</div>
