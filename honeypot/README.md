# 🍯 HoneyTrap — Python Honeypot Framework

A full-featured honeypot with web GUI, live event streaming, and 6 protocol emulators designed to appear **legitimate on nmap scans**.

---

## Quick Start (Windows)

```
double-click start.bat
```
or:
```
pip install -r requirements.txt
python honeypot.py
```

First launch runs a setup wizard to configure GUI credentials and port.

---

## Architecture

```
honeypot.py          — Main application (servers + Flask GUI)
templates/
  login.html         — Auth page
  dashboard.html     — Live GUI (WebSocket-driven)
logs/                — Per-protocol, per-day log files
requirements.txt
start.bat            — Windows launcher
```

---

## Protocol Details

| Protocol | Default Port | Transport | nmap Signature |
|----------|-------------|-----------|----------------|
| SSH      | 2222        | TCP       | Shows OpenSSH banner, RSA key exchange |
| FTP      | 2121        | TCP       | Shows vsFTPd/ProFTPD banner |
| HTTP     | 8888        | TCP       | Returns real HTTP headers with Server: banner |
| Telnet   | 2323        | TCP       | Full IAC negotiation, login prompt |
| SNMP     | 1161        | UDP       | Responds to GET requests (noSuchName) |
| SMB      | 4450        | TCP       | Returns SMBv1 negotiate response |

> **Note:** Ports above 1024 don't require Administrator. To use standard ports (22, 21, 80, 161, 445, 23) you need to run as Administrator and change port settings in the GUI.

---

## Making Protocols Appear Real to Nmap

### SSH
Uses `paramiko` for a real SSH handshake — nmap `-sV` will detect `OpenSSH` and the exact version from the banner.

### FTP
Sends real FTP 220 banner on connect. nmap detects the service + version string.

### HTTP
Returns proper `HTTP/1.1` responses with configurable `Server:` header. nmap `-sV` reads the banner.

### Telnet
Sends real IAC telnet negotiation bytes before the login prompt. nmap identifies as telnet.

### SNMP (UDP)
Responds to SNMP v1/v2c GET requests with a valid (but error) SNMP packet — nmap UDP scan sees an active SNMP agent.

### SMB
Returns a valid SMBv1 Negotiate Protocol Response with your OS string embedded. nmap `-sV` will fingerprint as Windows or Samba.

---

## Nmap Test Commands

```bash
# Scan all honeypot ports
nmap -sV -p 2121,2222,2323,4450,8888 <honeypot-ip>

# UDP SNMP
nmap -sU -p 1161 <honeypot-ip>

# Aggressive scan to trigger all logging
nmap -A -p 2121,2222,2323,4450,8888 <honeypot-ip>
```

---

## Web GUI Features

- **Overview** — Live stat cards per protocol (connections / alerts), recent event table
- **Live Feed** — Real-time WebSocket event stream with filtering (protocol, severity, IP search)
- **Protocol Control** — Start/stop each service independently, change port, set banner from presets or custom
- **Log Viewer** — Browse, search, and download daily logs per protocol

---

## Predefined Vulnerable Banners

### SSH
- `SSH-2.0-OpenSSH_7.4` — CVE-2017-15906 (sftp write)
- `SSH-2.0-OpenSSH_6.6` — Multiple auth bypass CVEs
- `SSH-2.0-dropbear_2016.74` — Old embedded router firmware
- `SSH-2.0-OpenSSH_5.3` — RHEL legacy

### FTP
- `220 (vsFTPd 2.3.4)` — **CVE-2011-2523** backdoor (port 6200)
- `220 ProFTPD 1.3.3c Server` — **CVE-2010-4221** buffer overflow
- `220-FileZilla Server version 0.9.41 beta` — Old FileZilla

### HTTP
- `Apache/2.2.8 (Ubuntu)` — CVE-2017-7679 mod_mime
- `Microsoft-IIS/6.0` — **CVE-2017-7269** buffer overflow
- `nginx/1.12.0` — Various older CVEs

### SMB
- `Windows XP Service Pack 3` — **EternalBlue / MS17-010**
- `Samba 3.5.0-Debian` — **CVE-2017-7494** SambaCry

---

## Log Format

```
[2024-01-15T14:32:11] [ALERT] [SSH] 192.168.1.50:54321 | AUTH_ATTEMPT | username=root password=toor
[2024-01-15T14:32:11] [INFO] [FTP] 10.0.0.5:44123 | USER | username=admin
```

Logs are written to `logs/<protocol>_YYYY-MM-DD.log` and `logs/combined_YYYY-MM-DD.log`.

---

## Extending

Add a new protocol by implementing:
```python
def run_myproto_server(port, banner, stop_event):
    # ... TCP/UDP socket logic
    # Call log_event() for all activity

SERVER_FUNCTIONS["myproto"] = run_myproto_server
```
Then add it to `DEFAULT_CONFIG["protocols"]` and `DEFAULT_BANNERS`.
