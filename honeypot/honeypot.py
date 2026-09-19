#!/usr/bin/env python3
"""
HoneyTrap - Python Honeypot Framework
Supports: HTTP, FTP, SSH, SNMP, SMB, Telnet
Web GUI with live feeds, alerts, and log management
"""

import asyncio
import socket
import threading
import logging
import json
import os
import sys
import time
import hashlib
import struct
import re
from datetime import datetime
from collections import deque, defaultdict
from functools import wraps

# Flask for Web GUI
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from flask_socketio import SocketIO, emit

# ─────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

CONFIG_FILE = "honeypot_config.json"
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Live event queue (last 500 events)
live_events = deque(maxlen=500)
alert_counts = defaultdict(int)
connection_stats = defaultdict(lambda: defaultdict(int))

# Active server threads
active_servers = {}
server_stop_events = {}

# ─────────────────────────────────────────────
# CONFIG MANAGEMENT
# ─────────────────────────────────────────────

DEFAULT_BANNERS = {
    "ssh": [
        {"name": "OpenSSH 7.4 (Vulnerable)", "value": "SSH-2.0-OpenSSH_7.4"},
        {"name": "OpenSSH 6.6 (Critical CVEs)", "value": "SSH-2.0-OpenSSH_6.6"},
        {"name": "Dropbear 2016.74", "value": "SSH-2.0-dropbear_2016.74"},
        {"name": "OpenSSH 5.3 (Legacy)", "value": "SSH-2.0-OpenSSH_5.3"},
        {"name": "Custom", "value": "SSH-2.0-OpenSSH_8.9"},
    ],
    "ftp": [
        {"name": "vsftpd 2.3.4 (Backdoor CVE-2011-2523)", "value": "220 (vsFTPd 2.3.4)"},
        {"name": "ProFTPD 1.3.3c (CVE-2010-4221)", "value": "220 ProFTPD 1.3.3c Server"},
        {"name": "FileZilla Server 0.9.41", "value": "220-FileZilla Server version 0.9.41 beta"},
        {"name": "Pure-FTPd (Generic)", "value": "220---------- Welcome to Pure-FTPd ----------"},
        {"name": "Microsoft FTP 7.5", "value": "220 Microsoft FTP Service"},
    ],
    "http": [
        {"name": "Apache 2.2.8 (CVE-2017-7679)", "value": "Apache/2.2.8 (Ubuntu)"},
        {"name": "IIS 6.0 (CVE-2017-7269)", "value": "Microsoft-IIS/6.0"},
        {"name": "nginx 1.12.0", "value": "nginx/1.12.0"},
        {"name": "Apache 2.4.7 (Ubuntu)", "value": "Apache/2.4.7 (Ubuntu)"},
        {"name": "lighttpd 1.4.35", "value": "lighttpd/1.4.35"},
    ],
    "telnet": [
        {"name": "Linux (Busybox)", "value": "\r\nBusyBox v1.26.2 built-in shell\r\n\r\nlogin: "},
        {"name": "Cisco IOS 12.4", "value": "\r\nUser Access Verification\r\n\r\nPassword: "},
        {"name": "Generic Linux", "value": "\r\nDebian GNU/Linux 8\r\n\r\nlogin: "},
        {"name": "Mikrotik RouterOS", "value": "\r\nMikroTik v6.40.5\r\nLogin: "},
        {"name": "Generic Login", "value": "\r\nlogin: "},
    ],
    "smb": [
        {"name": "Windows XP SP3 (EternalBlue)", "value": "Windows XP Service Pack 3"},
        {"name": "Windows Server 2003", "value": "Windows Server 2003 3790 Service Pack 2"},
        {"name": "Samba 3.5.0 (CVE-2017-7494)", "value": "Samba 3.5.0-Debian"},
        {"name": "Windows 7 (MS17-010)", "value": "Windows 7 Ultimate 7601 Service Pack 1"},
        {"name": "Samba 4.5.2", "value": "Samba 4.5.2-Debian"},
    ],
    "snmp": [
        {"name": "Net-SNMP 5.7.2", "value": "Linux honeypot 3.16.0 #1 SMP"},
        {"name": "Cisco IOS", "value": "Cisco Internetwork Operating System Software"},
        {"name": "Windows SNMP", "value": "Hardware: x86 - Software: Windows Version 5.2"},
        {"name": "Net-SNMP Generic", "value": "NET-SNMP version 5.5"},
    ]
}

DEFAULT_CONFIG = {
    "gui_username": "",
    "gui_password_hash": "",
    "gui_port": 8080,
    "protocols": {
        "http":   {"enabled": False, "port": 8888, "banner": "Apache/2.2.8 (Ubuntu)"},
        "ftp":    {"enabled": False, "port": 2121, "banner": "220 (vsFTPd 2.3.4)"},
        "ssh":    {"enabled": False, "port": 2222, "banner": "SSH-2.0-OpenSSH_7.4"},
        "snmp":   {"enabled": False, "port": 1161, "banner": "NET-SNMP version 5.5"},
        "smb":    {"enabled": False, "port": 4450, "banner": "Windows XP Service Pack 3"},
        "telnet": {"enabled": False, "port": 2323, "banner": "\r\nlogin: "},
    }
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ─────────────────────────────────────────────
# LOGGING ENGINE
# ─────────────────────────────────────────────

def get_log_file(protocol):
    today = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"{protocol}_{today}.log")

def log_event(protocol, src_ip, src_port, event_type, details, severity="INFO"):
    ts = datetime.now().isoformat()
    entry = {
        "timestamp": ts,
        "protocol": protocol.upper(),
        "src_ip": src_ip,
        "src_port": src_port,
        "event_type": event_type,
        "details": details,
        "severity": severity,
    }
    # File log
    log_line = f"[{ts}] [{severity}] [{protocol.upper()}] {src_ip}:{src_port} | {event_type} | {details}\n"
    with open(get_log_file(protocol), "a") as f:
        f.write(log_line)
    # Also write to combined log
    with open(get_log_file("combined"), "a") as f:
        f.write(log_line)

    # Update stats
    connection_stats[protocol]["total"] += 1
    if severity in ("ALERT", "CRITICAL"):
        connection_stats[protocol]["alerts"] += 1
        alert_counts[protocol] += 1

    live_events.appendleft(entry)

    # Push to WebSocket clients
    socketio.emit("new_event", entry)
    if severity in ("ALERT", "CRITICAL"):
        socketio.emit("new_alert", entry)

# ─────────────────────────────────────────────
# PROTOCOL SERVERS
# ─────────────────────────────────────────────

# ── SSH Honeypot ──────────────────────────────
def run_ssh_server(port, banner, stop_event):
    try:
        import paramiko
    except ImportError:
        log_event("ssh", "127.0.0.1", 0, "SERVER_ERROR", "paramiko not installed", "CRITICAL")
        return

    class HoneySSHServer(paramiko.ServerInterface):
        def __init__(self, client_ip):
            self.client_ip = client_ip
            self.event = threading.Event()

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_auth_password(self, username, password):
            log_event("ssh", self.client_ip, 0, "AUTH_ATTEMPT",
                      f"username={username} password={password}", "ALERT")
            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            log_event("ssh", self.client_ip, 0, "PUBKEY_AUTH",
                      f"username={username} key_type={key.get_name()}", "ALERT")
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password,publickey"

    # Generate or load host key
    host_key_file = "ssh_host_key"
    if not os.path.exists(host_key_file):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(host_key_file)
    else:
        key = paramiko.RSAKey(filename=host_key_file)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    sock.settimeout(1.0)
    log_event("ssh", "0.0.0.0", port, "SERVER_START", f"SSH honeypot listening on port {port} | banner: {banner}", "INFO")

    while not stop_event.is_set():
        try:
            client, addr = sock.accept()
        except socket.timeout:
            continue
        except Exception:
            break

        def handle(c, a):
            src_ip, src_port = a
            log_event("ssh", src_ip, src_port, "CONNECTION", "New SSH connection", "INFO")
            try:
                t = paramiko.Transport(c)
                t.local_version = banner
                t.add_server_key(key)
                server = HoneySSHServer(src_ip)
                t.start_server(server=server)
                chan = t.accept(10)
                if chan:
                    chan.close()
                t.close()
            except Exception as e:
                log_event("ssh", src_ip, src_port, "ERROR", str(e), "INFO")
            finally:
                c.close()

        threading.Thread(target=handle, args=(client, addr), daemon=True).start()

    sock.close()
    log_event("ssh", "0.0.0.0", port, "SERVER_STOP", "SSH honeypot stopped", "INFO")


# ── FTP Honeypot ──────────────────────────────
def run_ftp_server(port, banner, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    sock.settimeout(1.0)
    log_event("ftp", "0.0.0.0", port, "SERVER_START", f"FTP honeypot on port {port} | banner: {banner}", "INFO")

    def handle_client(conn, addr):
        src_ip, src_port = addr
        log_event("ftp", src_ip, src_port, "CONNECTION", "New FTP connection", "INFO")
        try:
            conn.sendall(f"{banner}\r\n".encode())
            username = None
            while True:
                data = conn.recv(1024).decode(errors="ignore").strip()
                if not data:
                    break
                cmd = data.upper().split()[0] if data.split() else ""
                args = data[len(cmd):].strip()

                if cmd == "USER":
                    username = args
                    log_event("ftp", src_ip, src_port, "USER", f"username={args}", "INFO")
                    conn.sendall(b"331 Password required\r\n")
                elif cmd == "PASS":
                    log_event("ftp", src_ip, src_port, "AUTH_ATTEMPT",
                              f"username={username} password={args}", "ALERT")
                    conn.sendall(b"530 Login incorrect.\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == "FEAT":
                    conn.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
                else:
                    log_event("ftp", src_ip, src_port, "COMMAND", f"cmd={cmd} args={args}", "INFO")
                    conn.sendall(b"530 Please login with USER and PASS.\r\n")
        except Exception as e:
            log_event("ftp", src_ip, src_port, "ERROR", str(e), "INFO")
        finally:
            conn.close()

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    log_event("ftp", "0.0.0.0", port, "SERVER_STOP", "FTP honeypot stopped", "INFO")


# ── HTTP Honeypot ─────────────────────────────
def run_http_server(port, banner, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(20)
    sock.settimeout(1.0)
    log_event("http", "0.0.0.0", port, "SERVER_START", f"HTTP honeypot on port {port} | server: {banner}", "INFO")

    FAKE_PAGES = {
        "/": ("<html><body><h1>It works!</h1><p>Apache/2.2.8 (Ubuntu) Server</p></body></html>", "200 OK"),
        "/admin": ("<html><body><h1>401 Authorization Required</h1></body></html>", "401 Unauthorized"),
        "/phpmyadmin": ("<html><body>phpMyAdmin login</body></html>", "200 OK"),
        "/wp-login.php": ("<html><body>WordPress Login</body></html>", "200 OK"),
        "/login": ("<html><body><form>Username:<input name=u> Password:<input name=p type=password><input type=submit></form></body></html>", "200 OK"),
        "/.env": ("DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123\nAPP_KEY=base64:secret", "200 OK"),
        "/etc/passwd": ("<html><body>403 Forbidden</body></html>", "403 Forbidden"),
    }

    def handle_client(conn, addr):
        src_ip, src_port = addr
        try:
            data = conn.recv(4096).decode(errors="ignore")
            if not data:
                return
            lines = data.split("\r\n")
            req_line = lines[0] if lines else ""
            parts = req_line.split()
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            user_agent = headers.get("user-agent", "unknown")
            log_event("http", src_ip, src_port, "HTTP_REQUEST",
                      f"method={method} path={path} ua={user_agent}", "INFO")

            # Detect scans / exploits
            suspicious = ["/etc/passwd", "/../", "/wp-config", "UNION SELECT", "<script", "cmd=", "exec(", "/shell"]
            severity = "ALERT" if any(s.lower() in path.lower() or s.lower() in data.lower() for s in suspicious) else "INFO"
            if severity == "ALERT":
                log_event("http", src_ip, src_port, "SUSPICIOUS_REQUEST",
                          f"path={path} possible exploit/scan", "ALERT")

            body, status = FAKE_PAGES.get(path, ("<html><body>404 Not Found</body></html>", "404 Not Found"))
            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Server: {banner}\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            conn.sendall(response.encode())
        except Exception as e:
            log_event("http", src_ip, src_port, "ERROR", str(e), "INFO")
        finally:
            conn.close()

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            src_ip, src_port = addr
            log_event("http", src_ip, src_port, "CONNECTION", "New HTTP connection", "INFO")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    log_event("http", "0.0.0.0", port, "SERVER_STOP", "HTTP honeypot stopped", "INFO")


# ── Telnet Honeypot ───────────────────────────
def run_telnet_server(port, banner, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    sock.settimeout(1.0)
    log_event("telnet", "0.0.0.0", port, "SERVER_START", f"Telnet honeypot on port {port}", "INFO")

    # Telnet negotiation bytes
    WILL_ECHO = bytes([255, 251, 1])
    WILL_SGA  = bytes([255, 251, 3])
    DO_TTYPE  = bytes([255, 253, 24])

    def handle_client(conn, addr):
        src_ip, src_port = addr
        log_event("telnet", src_ip, src_port, "CONNECTION", "New Telnet connection", "INFO")
        try:
            conn.sendall(WILL_ECHO + WILL_SGA + DO_TTYPE)
            conn.sendall(banner.encode())
            username = b""
            password = b""
            state = "user"
            conn.settimeout(30)
            buf = b""
            while True:
                try:
                    data = conn.recv(256)
                except socket.timeout:
                    break
                if not data:
                    break
                # Strip telnet IAC sequences
                i = 0
                clean = b""
                while i < len(data):
                    if data[i] == 255:
                        i += 3 if i + 1 < len(data) and data[i+1] in (251,252,253,254) else 2
                    else:
                        clean += bytes([data[i]])
                        i += 1
                buf += clean
                if b"\r" in buf or b"\n" in buf:
                    line = buf.split(b"\r")[0].split(b"\n")[0]
                    buf = b""
                    if state == "user":
                        username = line.decode(errors="ignore").strip()
                        log_event("telnet", src_ip, src_port, "USERNAME", f"username={username}", "INFO")
                        conn.sendall(b"Password: ")
                        state = "pass"
                    elif state == "pass":
                        password = line.decode(errors="ignore").strip()
                        log_event("telnet", src_ip, src_port, "AUTH_ATTEMPT",
                                  f"username={username} password={password}", "ALERT")
                        conn.sendall(b"\r\nLogin incorrect\r\n\r\nlogin: ")
                        state = "user"
        except Exception as e:
            log_event("telnet", src_ip, src_port, "ERROR", str(e), "INFO")
        finally:
            conn.close()

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    log_event("telnet", "0.0.0.0", port, "SERVER_STOP", "Telnet honeypot stopped", "INFO")


# ── SNMP Honeypot ─────────────────────────────
def run_snmp_server(port, banner, stop_event):
    """UDP-based SNMP honeypot responding to GET requests"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    log_event("snmp", "0.0.0.0", port, "SERVER_START", f"SNMP honeypot on UDP port {port} | sysDescr: {banner}", "INFO")

    def parse_community(data):
        """Very basic SNMP v1/v2c community string extraction"""
        try:
            # SNMP packet: 30 <len> 02 01 <ver> 04 <clen> <community> ...
            if len(data) < 10:
                return None
            idx = 0
            if data[idx] != 0x30:
                return None
            idx += 2  # skip sequence tag + length
            if data[idx] != 0x02:
                return None
            idx += 3  # skip integer tag, length, version value
            if data[idx] != 0x04:
                return None
            idx += 1
            clen = data[idx]
            idx += 1
            community = data[idx:idx+clen].decode(errors="ignore")
            return community
        except Exception:
            return None

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break

        src_ip, src_port = addr
        community = parse_community(data) or "unknown"
        log_event("snmp", src_ip, src_port, "SNMP_REQUEST",
                  f"community={community} len={len(data)}", "ALERT" if community not in ("public","private") else "INFO")

        # Send a minimal SNMP error response (noSuchName) to appear real
        try:
            # Minimal SNMP GetResponse - error status noSuchName
            # This makes scanners think there's a real SNMP agent
            response = bytes([
                0x30, 0x26,             # SEQUENCE
                0x02, 0x01, 0x01,       # version: 1
                0x04, 0x06]) + b"public" + bytes([
                0xa2, 0x19,             # GetResponse PDU
                0x02, 0x01, 0x00,       # request-id
                0x02, 0x01, 0x02,       # error-status: noSuchName
                0x02, 0x01, 0x00,       # error-index
                0x30, 0x0e,             # varbindlist
                0x30, 0x0c,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                0x05, 0x00              # NULL value
            ])
            sock.sendto(response, addr)
        except Exception:
            pass

    sock.close()
    log_event("snmp", "0.0.0.0", port, "SERVER_STOP", "SNMP honeypot stopped", "INFO")


# ── SMB Honeypot ──────────────────────────────
def run_smb_server(port, banner, stop_event):
    """TCP SMB honeypot - responds to SMB negotiation to appear real on nmap"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(10)
    sock.settimeout(1.0)
    log_event("smb", "0.0.0.0", port, "SERVER_START", f"SMB honeypot on port {port} | OS: {banner}", "INFO")

    # SMBv1 Negotiate Response (makes nmap identify as SMB)
    def make_smb_neg_response(os_name):
        os_b = (os_name + "\x00").encode("utf-16-le")
        domain_b = b"WORKGROUP\x00\x00"
        # Minimal valid SMBv1 negotiate response skeleton
        payload = bytes([
            0xFF,0x53,0x4D,0x42,  # SMB signature
            0x72,                  # Command: Negotiate
            0x00,0x00,0x00,0x00,  # NT Status: success
            0x98,                  # Flags
            0x53,0xC8,            # Flags2
            0x00,0x00,            # PID high
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  # Signature
            0x00,0x00,            # Reserved
            0x00,0x00,            # Tree ID
            0x00,0x00,            # PID
            0x00,0x00,            # UID
            0x01,0x00,            # MID
        ]) + bytes([
            0x11,                  # WordCount
            0x05,0x00,            # DialectIndex: NT LM 0.12
            0x03,                  # SecurityMode
            0x00,0x00,            # MaxMpxCount
            0x01,0x00,            # MaxCountVCs
            0x00,0x00,0x10,0x00, # MaxBufferSize
            0x00,0x00,0x10,0x00, # MaxRawSize
            0x01,0x00,0x00,0x00, # SessionKey
            0x40,0x00,0x00,0x00, # Capabilities
            0x00,0x00,0x00,0x00, # System time low
            0x00,0x00,0x00,0x00, # System time high
            0x00,0x00,            # ServerTimeZone
            0x00,                  # EncryptionKeyLength
        ]) + struct.pack("<H", 2 + len(domain_b) + len(os_b)) + b"\x00\x00" + domain_b + os_b

        # NetBIOS session header
        nb_header = struct.pack(">I", len(payload))
        return nb_header + payload

    def handle_client(conn, addr):
        src_ip, src_port = addr
        log_event("smb", src_ip, src_port, "CONNECTION", "New SMB connection", "INFO")
        try:
            conn.settimeout(15)
            data = conn.recv(1024)
            if not data:
                return
            # Check for SMB signature
            if len(data) > 8 and data[4:8] == b'\xff\x53\x4d\x42':
                cmd = data[8]
                log_event("smb", src_ip, src_port, "SMB_COMMAND",
                          f"SMBv1 command=0x{cmd:02x}", "ALERT" if cmd == 0x72 else "INFO")
                if cmd == 0x72:  # Negotiate
                    conn.sendall(make_smb_neg_response(banner))
            elif len(data) > 8 and data[4:8] == b'\xfeSMB':
                log_event("smb", src_ip, src_port, "SMB_COMMAND", "SMBv2/v3 negotiate attempt", "ALERT")
            else:
                log_event("smb", src_ip, src_port, "RAW_DATA",
                          f"raw={data[:32].hex()}", "INFO")
        except Exception as e:
            log_event("smb", src_ip, src_port, "ERROR", str(e), "INFO")
        finally:
            conn.close()

    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    log_event("smb", "0.0.0.0", port, "SERVER_STOP", "SMB honeypot stopped", "INFO")


# ─────────────────────────────────────────────
# SERVER MANAGEMENT
# ─────────────────────────────────────────────

SERVER_FUNCTIONS = {
    "ssh": run_ssh_server,
    "ftp": run_ftp_server,
    "http": run_http_server,
    "telnet": run_telnet_server,
    "snmp": run_snmp_server,
    "smb": run_smb_server,
}

def start_protocol(protocol, port, banner):
    if protocol in active_servers:
        return False, "Already running"
    stop_event = threading.Event()
    fn = SERVER_FUNCTIONS.get(protocol)
    if not fn:
        return False, "Unknown protocol"
    t = threading.Thread(target=fn, args=(port, banner, stop_event), daemon=True)
    t.start()
    active_servers[protocol] = t
    server_stop_events[protocol] = stop_event
    return True, "Started"

def stop_protocol(protocol):
    if protocol not in server_stop_events:
        return False, "Not running"
    server_stop_events[protocol].set()
    active_servers.pop(protocol, None)
    server_stop_events.pop(protocol, None)
    return True, "Stopped"


# ─────────────────────────────────────────────
# WEB GUI
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_config()
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == cfg["gui_username"] and hash_password(p) == cfg["gui_password_hash"]:
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/status")
@login_required
def api_status():
    cfg = load_config()
    status = {}
    for proto, pcfg in cfg["protocols"].items():
        status[proto] = {
            "running": proto in active_servers,
            "port": pcfg["port"],
            "banner": pcfg["banner"],
            "enabled": pcfg["enabled"],
            "total": connection_stats[proto]["total"],
            "alerts": connection_stats[proto]["alerts"],
        }
    return jsonify(status)

@app.route("/api/events")
@login_required
def api_events():
    limit = int(request.args.get("limit", 100))
    proto = request.args.get("protocol", "")
    severity = request.args.get("severity", "")
    events = list(live_events)
    if proto:
        events = [e for e in events if e["protocol"].lower() == proto.lower()]
    if severity:
        events = [e for e in events if e["severity"] == severity.upper()]
    return jsonify(events[:limit])

@app.route("/api/toggle", methods=["POST"])
@login_required
def api_toggle():
    data = request.json
    proto = data.get("protocol")
    action = data.get("action")  # "start" or "stop"
    cfg = load_config()

    if proto not in cfg["protocols"]:
        return jsonify({"success": False, "error": "Unknown protocol"})

    pcfg = cfg["protocols"][proto]

    if action == "start":
        ok, msg = start_protocol(proto, pcfg["port"], pcfg["banner"])
        if ok:
            cfg["protocols"][proto]["enabled"] = True
            save_config(cfg)
    elif action == "stop":
        ok, msg = stop_protocol(proto)
        if ok:
            cfg["protocols"][proto]["enabled"] = False
            save_config(cfg)
    else:
        return jsonify({"success": False, "error": "Unknown action"})

    return jsonify({"success": ok, "message": msg})

@app.route("/api/update_config", methods=["POST"])
@login_required
def api_update_config():
    data = request.json
    cfg = load_config()
    proto = data.get("protocol")
    if proto and proto in cfg["protocols"]:
        was_running = proto in active_servers
        if was_running:
            stop_protocol(proto)
        if "port" in data:
            cfg["protocols"][proto]["port"] = int(data["port"])
        if "banner" in data:
            cfg["protocols"][proto]["banner"] = data["banner"]
        save_config(cfg)
        if was_running:
            pcfg = cfg["protocols"][proto]
            start_protocol(proto, pcfg["port"], pcfg["banner"])
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Unknown protocol"})

@app.route("/api/logs")
@login_required
def api_logs():
    protocol = request.args.get("protocol", "combined")
    date = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    log_file = os.path.join(LOG_DIR, f"{protocol}_{date}.log")
    if not os.path.exists(log_file):
        return jsonify({"lines": [], "file": log_file})
    with open(log_file) as f:
        lines = f.readlines()
    return jsonify({"lines": lines[-500:], "file": log_file, "total": len(lines)})

@app.route("/api/download_log")
@login_required
def api_download_log():
    protocol = request.args.get("protocol", "combined")
    date = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    log_file = os.path.join(LOG_DIR, f"{protocol}_{date}.log")
    if not os.path.exists(log_file):
        return "Log not found", 404
    with open(log_file) as f:
        content = f.read()
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={protocol}_{date}.log"}
    )

@app.route("/api/alert_stats")
@login_required
def api_alert_stats():
    return jsonify(dict(alert_counts))

@app.route("/api/banners")
@login_required
def api_banners():
    return jsonify(DEFAULT_BANNERS)

@app.route("/api/clear_alerts", methods=["POST"])
@login_required
def api_clear_alerts():
    alert_counts.clear()
    return jsonify({"success": True})

# ─────────────────────────────────────────────
# SETUP WIZARD
# ─────────────────────────────────────────────

def setup_wizard():
    print("\n" + "═"*55)
    print("   🍯  HoneyTrap - Honeypot Framework  🍯")
    print("═"*55)
    print("\nFirst-time setup — configure GUI credentials\n")

    cfg = DEFAULT_CONFIG.copy()

    while True:
        username = input("  GUI Username: ").strip()
        if username:
            break
        print("  Username cannot be empty.")

    while True:
        import getpass
        password = getpass.getpass("  GUI Password: ")
        confirm  = getpass.getpass("  Confirm Password: ")
        if password == confirm and len(password) >= 6:
            break
        print("  Passwords must match and be at least 6 characters.")

    gui_port = input(f"  GUI Port [{cfg['gui_port']}]: ").strip()
    cfg["gui_port"] = int(gui_port) if gui_port.isdigit() else cfg["gui_port"]

    cfg["gui_username"] = username
    cfg["gui_password_hash"] = hash_password(password)
    save_config(cfg)
    print(f"\n  ✓ Config saved. GUI will start at http://localhost:{cfg['gui_port']}\n")
    return cfg


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cfg = load_config()

    # First-run setup
    if not cfg.get("gui_password_hash"):
        cfg = setup_wizard()

    # Auto-start previously enabled protocols
    for proto, pcfg in cfg["protocols"].items():
        if pcfg.get("enabled"):
            print(f"  [*] Auto-starting {proto.upper()} on port {pcfg['port']}")
            start_protocol(proto, pcfg["port"], pcfg["banner"])

    gui_port = cfg.get("gui_port", 8080)
    print(f"\n  [*] HoneyTrap GUI → http://localhost:{gui_port}")
    print(f"  [*] Login with username: {cfg['gui_username']}")
    print("  [*] Press Ctrl+C to stop all services\n")

    socketio.run(app, host="0.0.0.0", port=gui_port, debug=False, use_reloader=False)
