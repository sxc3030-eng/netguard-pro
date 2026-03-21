"""
NetGuard Pro - Moteur de surveillance réseau
Capture, analyse et bloque les paquets en temps réel
Auteur: NetGuard Pro
Version: 1.6.0
Usage: python netguard.py [--interface eth0] [--port 8765] [--no-block]
"""

import asyncio
import json
import logging
import argparse
import time
import threading
import platform
import ipaddress
import re
import struct
import socket
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Optional
import os
import sys

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[WARN] websockets non installé. Installe avec: pip install websockets")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, get_if_list
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[WARN] scapy non installé. Installe avec: pip install scapy")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

@dataclass
class Config:
    interface:              str   = "auto"
    ws_port:                int   = 8765
    can_block:              bool  = True
    log_file:               str   = "netguard.log"
    max_packets_log:        int   = 10_000
    port_scan_threshold:    int   = 15
    port_scan_window:       int   = 10
    brute_force_threshold:  int   = 8
    brute_force_window:     int   = 30
    syn_flood_threshold:    int   = 200
    syn_flood_window:       int   = 5
    dns_tunnel_threshold:   int   = 50
    whitelist: list = field(default_factory=lambda: [
        "127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"
    ])
    sensitive_ports:    list = field(default_factory=lambda: [22, 3389, 5900, 23])
    always_block_ports: list = field(default_factory=lambda: [135, 137, 138, 139, 445, 1433, 3306])
    record_enabled:     bool  = False
    record_dir:         str   = "captures"
    record_rotate_min:  int   = 60
    record_max_files:   int   = 24
    dpi_enabled:        bool  = True
    dpi_mask_sensitive: bool  = True
    auto_block_enabled: bool  = True
    auto_block_hits:    int   = 10

CFG = Config()

RULES = {
    "block_port_scan":   {"enabled": True,  "label": "Bloquer scan de ports",  "hits": 0},
    "block_ssh_external":{"enabled": True,  "label": "Bloquer SSH externe",    "hits": 0},
    "block_rdp_public":  {"enabled": True,  "label": "Bloquer RDP public",     "hits": 0},
    "block_tor_exits":   {"enabled": True,  "label": "Bloquer Tor exit nodes", "hits": 0},
    "block_p2p":         {"enabled": True,  "label": "Bloquer P2P/Torrent",    "hits": 0},
    "block_syn_flood":   {"enabled": True,  "label": "Bloquer SYN Flood",      "hits": 0},
    "block_brute_force": {"enabled": True,  "label": "Bloquer Brute Force",    "hits": 0},
    "alert_geo":         {"enabled": True,  "label": "Alerter trafic suspect", "hits": 0},
}

TOR_EXIT_NODES: set = set()
BLOCKED_IPS:    set = set()
BLOCKED_NETS:   list = []

KNOWN_BAD_RANGES = ["185.220.0.0/16", "162.247.74.0/24"]
P2P_PORTS = set(range(6881, 6890)) | {51413, 1337, 2710}

# ─── Géoblocage ────────────────────────────────────────────────────────────
GEO_BLOCKED_COUNTRIES: set = set()

GEO_IP_RANGES = {
    "RU": ["5.8.0.0/16","5.44.0.0/22","37.9.0.0/16","46.8.0.0/16","77.37.128.0/17",
           "80.73.0.0/18","81.162.0.0/16","82.138.0.0/17","83.149.0.0/17","84.201.0.0/16",
           "85.90.0.0/15","87.226.128.0/17","89.111.0.0/18","91.108.4.0/22","92.53.0.0/18",
           "93.153.128.0/17","94.25.0.0/16","95.165.0.0/16","109.86.0.0/15","176.14.0.0/16",
           "178.140.0.0/14","185.71.76.0/22","193.232.0.0/14","194.8.0.0/15","195.2.0.0/16"],
    "CN": ["1.0.1.0/24","1.0.2.0/23","27.0.0.0/13","36.0.0.0/11","39.0.0.0/8",
           "42.0.0.0/8","49.0.0.0/8","58.0.0.0/7","60.0.0.0/8","61.0.0.0/8",
           "101.0.0.0/8","106.0.0.0/8","110.0.0.0/7","112.0.0.0/7","114.0.0.0/8",
           "115.0.0.0/8","116.0.0.0/6","120.0.0.0/6","124.0.0.0/7","163.0.0.0/8",
           "171.0.0.0/8","175.0.0.0/8","180.0.0.0/6","182.0.0.0/7","183.0.0.0/8"],
    "KP": ["175.45.176.0/22","210.52.109.0/24"],
    "IR": ["2.144.0.0/13","5.22.0.0/15","5.52.0.0/14","31.2.128.0/17","37.98.128.0/17",
           "37.156.0.0/16","46.100.0.0/14","62.60.0.0/15","78.39.192.0/18","80.71.0.0/17",
           "82.99.192.0/18","85.133.0.0/16","87.107.0.0/16","89.32.0.0/14","91.98.0.0/15",
           "94.182.0.0/15","95.38.0.0/15","109.120.128.0/17","176.65.192.0/18",
           "188.136.0.0/13","194.225.0.0/16","195.146.32.0/19"],
    "KR": ["1.16.0.0/12","1.176.0.0/12","14.0.0.0/11","27.96.0.0/14","49.142.0.0/17",
           "58.120.0.0/13","59.0.0.0/11","61.32.0.0/13","61.40.0.0/13","112.144.0.0/12",
           "119.64.0.0/11","121.128.0.0/11","122.32.0.0/11","125.128.0.0/11",
           "175.192.0.0/11","203.226.0.0/15","210.94.0.0/15","211.36.0.0/14"],
    "BR": ["177.0.0.0/8","179.0.0.0/8","186.192.0.0/11","189.0.0.0/8","200.128.0.0/9","201.0.0.0/8"],
    "NG": ["41.58.0.0/16","41.184.0.0/14","105.112.0.0/12","154.120.0.0/13","197.210.0.0/15","197.242.0.0/15"],
    "IN": ["1.6.0.0/15","14.96.0.0/11","27.4.0.0/14","43.224.0.0/11","45.112.0.0/12",
           "49.32.0.0/12","59.88.0.0/13","103.0.0.0/8","106.64.0.0/10","115.240.0.0/13",
           "117.192.0.0/11","119.224.0.0/11","122.160.0.0/11","180.64.0.0/12","182.64.0.0/10"],
    "US": ["3.0.0.0/8","4.0.0.0/8","8.0.0.0/8","12.0.0.0/8","13.0.0.0/8",
           "15.0.0.0/8","17.0.0.0/8","18.0.0.0/8","23.0.0.0/8","24.0.0.0/8",
           "34.0.0.0/8","35.0.0.0/8","44.0.0.0/8","45.0.0.0/8","52.0.0.0/8",
           "54.0.0.0/8","64.0.0.0/8","65.0.0.0/8","66.0.0.0/8","67.0.0.0/8"],
    "DE": ["5.1.0.0/17","46.4.0.0/14","78.42.0.0/15","80.154.0.0/15","81.169.0.0/16",
           "82.113.0.0/16","84.44.0.0/14","85.14.0.0/15","87.77.0.0/16","89.0.0.0/16",
           "91.65.0.0/16","94.130.0.0/15","213.160.0.0/14"],
    "FR": ["2.0.0.0/11","37.187.0.0/16","46.105.0.0/16","51.77.0.0/16","77.136.0.0/13",
           "78.192.0.0/11","82.64.0.0/11","83.200.0.0/13","86.192.0.0/11","88.120.0.0/13",
           "90.0.0.0/11","109.0.0.0/12","176.139.0.0/16","178.116.0.0/14"],
    "NL": ["2.56.0.0/14","31.3.0.0/16","37.19.0.0/16","45.14.0.0/16","77.243.0.0/16",
           "80.65.0.0/17","82.94.0.0/15","84.22.0.0/15","85.17.0.0/16","87.213.0.0/16",
           "89.188.0.0/15","94.75.0.0/16","95.211.0.0/16","185.220.0.0/16"],
}

GEO_COUNTRY_NAMES = {
    "RU":"Russie","CN":"Chine","KP":"Corée du Nord","IR":"Iran",
    "KR":"Corée du Sud","BR":"Brésil","NG":"Nigeria","IN":"Inde",
    "US":"États-Unis","DE":"Allemagne","FR":"France","NL":"Pays-Bas",
}

_geo_cache: dict = {}

def get_country(ip: str) -> Optional[str]:
    if is_private(ip):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
        for country, ranges in GEO_IP_RANGES.items():
            for net_str in ranges:
                try:
                    if addr in ipaddress.ip_network(net_str, strict=False):
                        _geo_cache[ip] = country
                        return country
                except ValueError:
                    pass
    except ValueError:
        pass
    _geo_cache[ip] = None
    return None

class NetState:
    def __init__(self):
        self.lock                  = threading.Lock()
        self.packets_total         = 0
        self.packets_blocked       = 0
        self.packets_allowed       = 0
        self.bytes_in              = 0
        self.bytes_out             = 0
        self.active_conns          = defaultdict(set)
        self.threats               = deque(maxlen=100)
        self.recent_packets        = deque(maxlen=500)
        self.geo_hits              = defaultdict(int)
        self.proto_stats           = defaultdict(int)
        self.traffic_history       = deque(maxlen=60)
        self._port_scan_tracker    = defaultdict(list)
        self._brute_force_tracker  = defaultdict(list)
        self._syn_flood_tracker    = defaultdict(list)
        self._dns_tracker          = defaultdict(list)
        self.ip_hit_counter        = defaultdict(int)
        self.dpi_alerts            = deque(maxlen=200)
        self.suricata_alerts       = deque(maxlen=200)
        self.record_active         = False
        self.record_file           = None
        self.record_file_path      = ""
        self.record_packets        = []
        self.record_start_time     = None
        self.record_lock           = threading.Lock()

STATE = NetState()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(CFG.log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("netguard")

_SENSITIVE_PATTERNS = [
    (re.compile(rb'password\s*[=:]\s*\S+', re.I),               "password"),
    (re.compile(rb'passwd\s*[=:]\s*\S+', re.I),                 "passwd"),
    (re.compile(rb'token\s*[=:]\s*[A-Za-z0-9+/=]{10,}', re.I), "token"),
    (re.compile(rb'Authorization:\s*\S+', re.I),                 "auth-header"),
    (re.compile(rb'Cookie:\s*\S+', re.I),                        "cookie"),
    (re.compile(rb'\b4[0-9]{12}(?:[0-9]{3})?\b'),               "card-visa"),
    (re.compile(rb'\b5[1-5][0-9]{14}\b'),                        "card-mc"),
]

_ATTACK_PATTERNS = [
    (re.compile(rb"(?:union\s+select|select\s+\*|drop\s+table|insert\s+into)", re.I), "SQL Injection"),
    (re.compile(rb"<script[\s>]", re.I),                                               "XSS"),
    (re.compile(rb"\.\./|\.\.\\"),                                                     "Path Traversal"),
    (re.compile(rb"(?:;|\|)\s*(?:ls|cat|whoami|id|pwd|wget|curl)\b", re.I),           "Command Injection"),
    (re.compile(rb"(?:169\.254\.169\.254|metadata\.google\.internal)", re.I),          "SSRF"),
    (re.compile(rb"\$\{jndi:", re.I),                                                  "Log4Shell"),
    (re.compile(rb"(?:masscan|zgrab|nmap|nikto|sqlmap|dirbuster|gobuster)", re.I),    "Scanner"),
]

# ─── Suricata IDS — règles intégrées + Emerging Threats ──────────────────
SURICATA_ENABLED: bool = True
SURICATA_RULES:   list = []   # liste de dicts {sid, msg, pattern, proto, action}
SURICATA_LOADED:  int  = 0    # nb de règles chargées

ET_RULESETS = {
    "et_scan":    "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-scan.rules",
    "et_exploit": "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-exploit.rules",
    "et_malware": "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-malware.rules",
    "et_dos":     "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-dos.rules",
}

# 27 règles intégrées — fonctionnent sans internet
BUILTIN_ET_RULES = [
    # Log4Shell
    {"sid":9000001,"msg":"ET EXPLOIT Apache Log4j RCE Attempt (jndi)","pattern":rb"\$\{jndi:","proto":"TCP","action":"alert","severity":"critical"},
    # EternalBlue
    {"sid":9000002,"msg":"ET EXPLOIT MS17-010 EternalBlue SMB","pattern":rb"\x00\x00\x00\x85\xff\x53\x4d\x42","proto":"TCP","action":"alert","severity":"critical"},
    # ShellShock
    {"sid":9000003,"msg":"ET EXPLOIT GNU Bash ShellShock Attack","pattern":rb"\(\s*\)\s*\{[^}]*\}\s*;","proto":"TCP","action":"alert","severity":"critical"},
    # Spring4Shell
    {"sid":9000004,"msg":"ET EXPLOIT Spring4Shell RCE Attempt","pattern":rb"class\.module\.classLoader","proto":"TCP","action":"alert","severity":"critical"},
    # Cobalt Strike
    {"sid":9000005,"msg":"ET MALWARE Cobalt Strike Beacon","pattern":rb"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.{16}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","proto":"TCP","action":"alert","severity":"high"},
    # Metasploit
    {"sid":9000006,"msg":"ET EXPLOIT Metasploit Meterpreter Stage","pattern":rb"MACE\x00\x00\x00","proto":"TCP","action":"alert","severity":"critical"},
    # AsyncRAT
    {"sid":9000007,"msg":"ET MALWARE AsyncRAT C2","pattern":rb"asyncrat|AsyncRAT","proto":"TCP","action":"alert","severity":"high"},
    # Mimikatz
    {"sid":9000008,"msg":"ET MALWARE Mimikatz Credential Dumping","pattern":rb"mimikatz|sekurlsa|lsadump","proto":"TCP","action":"alert","severity":"critical"},
    # Crypto Mining Stratum
    {"sid":9000009,"msg":"ET MALWARE CryptoMiner Stratum Protocol","pattern":rb'"method"\s*:\s*"mining\.(subscribe|authorize|submit)"',"proto":"TCP","action":"alert","severity":"high"},
    # XMRig
    {"sid":9000010,"msg":"ET MALWARE XMRig CryptoMiner","pattern":rb"xmrig|XMRig","proto":"TCP","action":"alert","severity":"high"},
    # SQL Injection
    {"sid":9000011,"msg":"ET WEB_SERVER SQL Injection Attempt","pattern":rb"(?:union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into\s+)","proto":"TCP","action":"alert","severity":"high"},
    # XSS
    {"sid":9000012,"msg":"ET WEB_SERVER XSS Attempt","pattern":rb"<script[\s>].*?(?:alert|document\.cookie|window\.location)","proto":"TCP","action":"alert","severity":"med"},
    # Path Traversal
    {"sid":9000013,"msg":"ET WEB_SERVER Path Traversal Attempt","pattern":rb"(?:\.\./){3,}","proto":"TCP","action":"alert","severity":"med"},
    # Command Injection
    {"sid":9000014,"msg":"ET WEB_SERVER Command Injection Attempt","pattern":rb"(?:;|\|)\s*(?:id|whoami|uname|cat\s+/etc/passwd|wget|curl)\b","proto":"TCP","action":"alert","severity":"high"},
    # SSRF
    {"sid":9000015,"msg":"ET WEB_SERVER SSRF Attempt AWS Metadata","pattern":rb"169\.254\.169\.254","proto":"TCP","action":"alert","severity":"high"},
    # DNS Tor
    {"sid":9000016,"msg":"ET POLICY DNS Query for Tor .onion Domain","pattern":rb"\.onion\x00","proto":"UDP","action":"alert","severity":"med"},
    # Ngrok Tunnel
    {"sid":9000017,"msg":"ET POLICY Ngrok Tunnel Detected","pattern":rb"ngrok\.io|ngrok\.com","proto":"TCP","action":"alert","severity":"med"},
    # Nmap scan
    {"sid":9000018,"msg":"ET SCAN Nmap Scripting Engine","pattern":rb"Nmap Scripting Engine|nmap\.org","proto":"TCP","action":"alert","severity":"low"},
    # Nikto scan
    {"sid":9000019,"msg":"ET SCAN Nikto Web Scanner","pattern":rb"Nikto/","proto":"TCP","action":"alert","severity":"low"},
    # SQLmap
    {"sid":9000020,"msg":"ET SCAN SQLmap SQL Injection Scanner","pattern":rb"sqlmap/","proto":"TCP","action":"alert","severity":"med"},
    # WannaCry
    {"sid":9000021,"msg":"ET EXPLOIT WannaCry Ransomware SMB","pattern":rb"WANNACRY|WanaCrypt0r","proto":"TCP","action":"alert","severity":"critical"},
    # Emotet
    {"sid":9000022,"msg":"ET MALWARE Emotet C2 Checkin","pattern":rb"emotet","proto":"TCP","action":"alert","severity":"critical"},
    # Heartbleed
    {"sid":9000023,"msg":"ET EXPLOIT OpenSSL Heartbleed","pattern":rb"\x18\x03[\x00-\x03]\x00\x03\x01\x40\x00","proto":"TCP","action":"alert","severity":"critical"},
    # BlueKeep
    {"sid":9000024,"msg":"ET EXPLOIT BlueKeep RDP RCE","pattern":rb"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00","proto":"TCP","action":"alert","severity":"critical"},
    # Reverse Shell
    {"sid":9000025,"msg":"ET MALWARE Reverse Shell Attempt","pattern":rb"(?:bash -i|/bin/sh -i|nc -e|ncat -e)","proto":"TCP","action":"alert","severity":"critical"},
    # Proxy HTTP CONNECT
    {"sid":9000026,"msg":"ET POLICY HTTP CONNECT Tunnel","pattern":rb"CONNECT .+:\d+ HTTP/","proto":"TCP","action":"alert","severity":"low"},
    # Default creds
    {"sid":9000027,"msg":"ET EXPLOIT Default Credentials Attempt","pattern":rb"admin:admin|admin:password|root:root|admin:123456","proto":"TCP","action":"alert","severity":"high"},
]

def _compile_builtin_rules() -> list:
    compiled = []
    for r in BUILTIN_ET_RULES:
        try:
            compiled.append({
                "sid":      r["sid"],
                "msg":      r["msg"],
                "pattern":  re.compile(r["pattern"], re.DOTALL | re.IGNORECASE),
                "proto":    r["proto"],
                "action":   r["action"],
                "severity": r["severity"],
            })
        except Exception:
            pass
    return compiled

def _parse_rule_line(line: str) -> Optional[dict]:
    """Parse une règle Suricata/Snort format texte"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Extraire msg
    msg_m = re.search(r'msg\s*:\s*"([^"]+)"', line)
    sid_m = re.search(r'sid\s*:\s*(\d+)', line)
    cont_m = re.search(r'content\s*:\s*"([^"]+)"', line)
    pcre_m = re.search(r'pcre\s*:\s*"([^"]+)"', line)
    if not msg_m:
        return None
    msg = msg_m.group(1)
    sid = int(sid_m.group(1)) if sid_m else 0
    severity = "high" if any(x in msg.upper() for x in ["EXPLOIT","MALWARE","CRITICAL"]) else \
               "med"  if any(x in msg.upper() for x in ["WEB","POLICY","TROJAN"]) else "low"
    # Essayer PCRE d'abord, sinon content
    pattern = None
    if pcre_m:
        try:
            raw = pcre_m.group(1)
            # Retirer les flags Snort (/i, /s, etc.)
            raw = re.sub(r'[/][gimsuy]*$', '', raw).lstrip('/')
            pattern = re.compile(raw.encode(), re.DOTALL | re.IGNORECASE)
        except Exception:
            pattern = None
    if pattern is None and cont_m:
        try:
            raw = cont_m.group(1).encode()
            pattern = re.compile(re.escape(raw), re.DOTALL | re.IGNORECASE)
        except Exception:
            return None
    if pattern is None:
        return None
    return {"sid": sid, "msg": msg, "pattern": pattern, "proto": "TCP", "action": "alert", "severity": severity}

def load_et_rules_online(ruleset_key: str) -> dict:
    """Télécharge un ruleset Emerging Threats depuis internet"""
    import urllib.request
    url = ET_RULESETS.get(ruleset_key)
    if not url:
        return {"ok": False, "error": f"Ruleset inconnu: {ruleset_key}"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/1.6"})
        with urllib.request.urlopen(req, timeout=15) as r:
            content = r.read().decode("utf-8", errors="ignore")
        rules = []
        for line in content.splitlines():
            parsed = _parse_rule_line(line)
            if parsed:
                rules.append(parsed)
        global SURICATA_RULES, SURICATA_LOADED
        # Ajouter sans doublon (par sid)
        existing_sids = {r["sid"] for r in SURICATA_RULES}
        added = 0
        for r in rules:
            if r["sid"] not in existing_sids:
                SURICATA_RULES.append(r)
                existing_sids.add(r["sid"])
                added += 1
        SURICATA_LOADED = len(SURICATA_RULES)
        log.info(f"[SURICATA] {ruleset_key}: +{added} règles chargées (total: {SURICATA_LOADED})")
        return {"ok": True, "added": added, "total": SURICATA_LOADED}
    except Exception as e:
        log.error(f"[SURICATA] Erreur chargement {ruleset_key}: {e}")
        return {"ok": False, "error": str(e)}

def suricata_match(src_ip: str, payload: bytes, proto: str) -> list:
    """Teste le payload contre toutes les règles Suricata actives"""
    if not SURICATA_ENABLED or not payload or not SURICATA_RULES:
        return []
    hits = []
    for rule in SURICATA_RULES:
        if rule.get("proto", "TCP") not in (proto, "ANY"):
            continue
        try:
            if rule["pattern"].search(payload):
                hits.append({
                    "sid":      rule["sid"],
                    "msg":      rule["msg"],
                    "severity": rule["severity"],
                    "action":   rule["action"],
                })
        except Exception:
            pass
    return hits

# Charger les règles intégrées au démarrage
SURICATA_RULES = _compile_builtin_rules()
SURICATA_LOADED = len(SURICATA_RULES)
print(f"[SURICATA] {SURICATA_LOADED} règles intégrées chargées")

def dpi_inspect(src_ip: str, payload: bytes) -> list:
    if not payload:
        return []
    alerts = []
    if CFG.dpi_mask_sensitive:
        for pattern, label in _SENSITIVE_PATTERNS:
            if pattern.search(payload):
                alerts.append({"type": "sensitive", "detail": label, "masked": True})
    for pattern, label in _ATTACK_PATTERNS:
        if pattern.search(payload):
            alerts.append({"type": "attack", "detail": label, "masked": False})
    return alerts

def _record_filename() -> str:
    os.makedirs(CFG.record_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(CFG.record_dir, f"capture_{ts}.pcap")

def _write_pcap_global_header(f):
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

def _write_pcap_record(f, raw_bytes: bytes):
    ts = time.time()
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    length  = len(raw_bytes)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
    f.write(raw_bytes)

def record_start():
    with STATE.record_lock:
        if STATE.record_active:
            return False
        path = _record_filename()
        STATE.record_file_path = path
        STATE.record_file = open(path, "wb")
        _write_pcap_global_header(STATE.record_file)
        STATE.record_active = True
        STATE.record_start_time = datetime.now()
        STATE.record_packets = []
    log.info(f"[RECORD] Démarré → {path}")
    return True

def record_stop() -> str:
    with STATE.record_lock:
        if not STATE.record_active:
            return ""
        STATE.record_active = False
        if STATE.record_file:
            STATE.record_file.flush()
            STATE.record_file.close()
            STATE.record_file = None
        path = STATE.record_file_path
    log.info(f"[RECORD] Arrêté → {path}")
    return path

def record_write_packet(raw_bytes: bytes):
    with STATE.record_lock:
        if not STATE.record_active or not STATE.record_file:
            return
        _write_pcap_record(STATE.record_file, raw_bytes)
        STATE.record_packets.append(len(raw_bytes))
        if STATE.record_start_time:
            elapsed = (datetime.now() - STATE.record_start_time).total_seconds()
            if elapsed >= CFG.record_rotate_min * 60:
                STATE.record_file.flush()
                STATE.record_file.close()
                STATE.record_file = None
                STATE.record_active = False
                log.info("[RECORD] Rotation automatique")
                _cleanup_old_captures()

def _cleanup_old_captures():
    try:
        files = sorted(
            [f for f in os.listdir(CFG.record_dir) if f.endswith(".pcap")],
            key=lambda f: os.path.getmtime(os.path.join(CFG.record_dir, f))
        )
        while len(files) > CFG.record_max_files:
            oldest = os.path.join(CFG.record_dir, files.pop(0))
            os.remove(oldest)
            log.info(f"[RECORD] Supprimé: {oldest}")
    except Exception as e:
        log.error(f"[RECORD] Erreur nettoyage: {e}")

def record_list() -> list:
    try:
        os.makedirs(CFG.record_dir, exist_ok=True)
        files = []
        for f in sorted(os.listdir(CFG.record_dir)):
            if not f.endswith(".pcap"):
                continue
            path = os.path.join(CFG.record_dir, f)
            size  = os.path.getsize(path)
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            files.append({"name": f, "path": path, "size": size, "date": mtime})
        return files
    except Exception:
        return []

def auto_block_check(src_ip: str):
    if not CFG.auto_block_enabled:
        return
    if is_whitelisted(src_ip) or is_private(src_ip):
        return
    STATE.ip_hit_counter[src_ip] += 1
    if STATE.ip_hit_counter[src_ip] >= CFG.auto_block_hits:
        if src_ip not in BLOCKED_IPS:
            block_ip_os(src_ip, f"Auto-block: {STATE.ip_hit_counter[src_ip]} hits")
            add_threat(src_ip, "Auto-block", f"Seuil de {CFG.auto_block_hits} hits atteint", "high")

def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False

def is_whitelisted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        for entry in CFG.whitelist:
            try:
                if "/" in entry:
                    if a in ipaddress.ip_network(entry, strict=False):
                        return True
                elif str(a) == entry:
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False

def is_in_bad_range(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        for net_str in KNOWN_BAD_RANGES:
            if a in ipaddress.ip_network(net_str, strict=False):
                return True
    except ValueError:
        pass
    return False

def get_protocol_name(pkt) -> str:
    if HAS_SCAPY:
        if pkt.haslayer(DNS):  return "DNS"
        if pkt.haslayer(TCP):
            dp = pkt[TCP].dport
            if dp == 443:  return "HTTPS"
            if dp == 80:   return "HTTP"
            if dp == 22:   return "SSH"
            if dp == 21:   return "FTP"
            if dp == 25:   return "SMTP"
            if dp == 3389: return "RDP"
            return "TCP"
        if pkt.haslayer(UDP):  return "UDP"
        if pkt.haslayer(ICMP): return "ICMP"
        if pkt.haslayer(ARP):  return "ARP"
    return "OTHER"

def block_ip_os(ip: str, reason: str):
    if ip in BLOCKED_IPS:
        return
    BLOCKED_IPS.add(ip)
    log.warning(f"[BLOCK] {ip} — {reason}")
    if not CFG.can_block:
        return
    try:
        if IS_LINUX:
            os.system(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null")
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            os.system(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes')
    except Exception as e:
        log.error(f"Erreur blocage OS pour {ip}: {e}")

def unblock_ip_os(ip: str):
    BLOCKED_IPS.discard(ip)
    try:
        if IS_LINUX:
            os.system(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            os.system(f'netsh advfirewall firewall delete rule name="{rule_name}"')
    except Exception as e:
        log.error(f"Erreur déblocage OS pour {ip}: {e}")

def add_threat(src_ip: str, threat_type: str, description: str, severity: str, rule_key: str = None):
    threat = {
        "id":          int(time.time() * 1000),
        "timestamp":   datetime.now().isoformat(),
        "src_ip":      src_ip,
        "type":        threat_type,
        "description": description,
        "severity":    severity,
        "blocked":     src_ip in BLOCKED_IPS,
    }
    STATE.threats.appendleft(threat)
    if rule_key and rule_key in RULES:
        RULES[rule_key]["hits"] += 1
    log.warning(f"[THREAT/{severity.upper()}] {threat_type} — {src_ip} — {description}")
    return threat

def _clean_window(lst: list, window: int) -> list:
    cutoff = time.time() - window
    return [t for t in lst if t > cutoff]

def detect_port_scan(src_ip: str, dst_port: int) -> Optional[str]:
    if not RULES["block_port_scan"]["enabled"]:
        return None
    tracker = STATE._port_scan_tracker[src_ip]
    now = time.time()
    tracker.append((now, dst_port))
    STATE._port_scan_tracker[src_ip] = [(t, p) for t, p in tracker if t > now - CFG.port_scan_window]
    unique_ports = len({p for _, p in STATE._port_scan_tracker[src_ip]})
    if unique_ports >= CFG.port_scan_threshold:
        return f"Scan de {unique_ports} ports en {CFG.port_scan_window}s"
    return None

def detect_brute_force(src_ip: str, dst_port: int, is_syn: bool) -> Optional[str]:
    if not RULES["block_brute_force"]["enabled"] or dst_port not in CFG.sensitive_ports or not is_syn:
        return None
    tracker = STATE._brute_force_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._brute_force_tracker[src_ip] = _clean_window(tracker, CFG.brute_force_window)
    count = len(STATE._brute_force_tracker[src_ip])
    if count >= CFG.brute_force_threshold:
        port_name = {22: "SSH", 3389: "RDP", 5900: "VNC", 23: "Telnet"}.get(dst_port, str(dst_port))
        return f"Brute Force {port_name}: {count} tentatives/{CFG.brute_force_window}s"
    return None

def detect_syn_flood(src_ip: str, is_syn: bool) -> Optional[str]:
    if not RULES["block_syn_flood"]["enabled"] or not is_syn:
        return None
    tracker = STATE._syn_flood_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._syn_flood_tracker[src_ip] = _clean_window(tracker, CFG.syn_flood_window)
    count = len(STATE._syn_flood_tracker[src_ip])
    if count >= CFG.syn_flood_threshold:
        return f"SYN Flood: {count} SYN/{CFG.syn_flood_window}s"
    return None

def detect_dns_tunneling(src_ip: str) -> Optional[str]:
    tracker = STATE._dns_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    STATE._dns_tracker[src_ip] = _clean_window(tracker, 5)
    count = len(STATE._dns_tracker[src_ip])
    if count >= CFG.dns_tunnel_threshold:
        return f"DNS Tunneling probable: {count} requêtes/5s"
    return None

def analyze_packet(pkt):
    if not HAS_SCAPY or not pkt.haslayer(IP):
        return

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    pkt_len  = len(pkt)
    proto    = get_protocol_name(pkt)
    dst_port = 0
    src_port = 0
    flags    = ""
    is_syn   = False

    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        src_port = pkt[TCP].sport
        flags    = str(pkt[TCP].flags)
        is_syn   = "S" in flags and "A" not in flags
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
        src_port = pkt[UDP].sport

    if STATE.record_active:
        try:
            record_write_packet(bytes(pkt))
        except Exception:
            pass

    decision = "allow"
    reason   = ""

    with STATE.lock:
        STATE.packets_total += 1
        STATE.proto_stats[proto] += 1

        if is_private(dst_ip):
            STATE.bytes_in += pkt_len
        else:
            STATE.bytes_out += pkt_len

        if src_ip in BLOCKED_IPS:
            decision = "block"
            reason   = "IP blacklistée"
        elif is_in_bad_range(src_ip):
            decision = "block"
            reason   = "IP dans plage malveillante"
            block_ip_os(src_ip, reason)
        elif not is_private(src_ip) and dst_port in CFG.always_block_ports:
            decision = "block"
            reason   = f"Port {dst_port} toujours bloqué"

        elif GEO_BLOCKED_COUNTRIES and not is_private(src_ip):
            country = get_country(src_ip)
            if country and country in GEO_BLOCKED_COUNTRIES:
                decision = "block"
                reason   = f"Géoblocage: {GEO_COUNTRY_NAMES.get(country, country)}"
                RULES["alert_geo"]["hits"] += 1
                block_ip_os(src_ip, reason)
        elif not is_private(src_ip) and dst_port in CFG.sensitive_ports and RULES["block_ssh_external"]["enabled"]:
            decision = "block"
            reason   = f"Accès port sensible ({dst_port}) depuis IP externe"
            RULES["block_ssh_external"]["hits"] += 1
        elif (dst_port in P2P_PORTS or src_port in P2P_PORTS) and RULES["block_p2p"]["enabled"]:
            decision = "block"
            reason   = "Trafic P2P/BitTorrent"
            RULES["block_p2p"]["hits"] += 1
        else:
            if not is_private(src_ip):
                scan_reason = detect_port_scan(src_ip, dst_port)
                if scan_reason:
                    decision = "block"
                    reason   = scan_reason
                    add_threat(src_ip, "Scan de ports", scan_reason, "high", "block_port_scan")
                    block_ip_os(src_ip, scan_reason)

                if decision == "allow":
                    bf_reason = detect_brute_force(src_ip, dst_port, is_syn)
                    if bf_reason:
                        decision = "block"
                        reason   = bf_reason
                        add_threat(src_ip, "Brute Force", bf_reason, "high", "block_brute_force")
                        block_ip_os(src_ip, bf_reason)

                if decision == "allow":
                    syn_reason = detect_syn_flood(src_ip, is_syn)
                    if syn_reason:
                        decision = "block"
                        reason   = syn_reason
                        add_threat(src_ip, "SYN Flood", syn_reason, "high", "block_syn_flood")
                        block_ip_os(src_ip, syn_reason)

            if decision == "allow" and pkt.haslayer(DNS):
                dns_reason = detect_dns_tunneling(src_ip)
                if dns_reason:
                    decision = "warn"
                    reason   = dns_reason
                    add_threat(src_ip, "DNS Tunneling", dns_reason, "med")

        if CFG.dpi_enabled and decision == "allow":
            payload = b""
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            if payload:
                for hit in dpi_inspect(src_ip, payload):
                    alert = {
                        "ts":     datetime.now().strftime("%H:%M:%S"),
                        "src":    src_ip,
                        "type":   hit["type"],
                        "detail": hit["detail"],
                        "masked": hit["masked"],
                    }
                    STATE.dpi_alerts.appendleft(alert)
                    if hit["type"] == "attack":
                        add_threat(src_ip, f"DPI: {hit['detail']}", f"Payload suspect", "high")
                        auto_block_check(src_ip)

        # ── Suricata IDS ───────────────────────────────────────────────
        if SURICATA_ENABLED and decision == "allow":
            payload = b""
            if HAS_SCAPY and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            if payload:
                for hit in suricata_match(src_ip, payload, proto):
                    alert = {
                        "ts":       datetime.now().strftime("%H:%M:%S"),
                        "src":      src_ip,
                        "sid":      hit["sid"],
                        "msg":      hit["msg"],
                        "severity": hit["severity"],
                    }
                    STATE.suricata_alerts.appendleft(alert)
                    add_threat(src_ip, f"IDS: {hit['msg']}", f"Règle #{hit['sid']} déclenchée", hit["severity"])
                    if hit["severity"] in ("critical", "high"):
                        auto_block_check(src_ip)

        if decision == "block" and not is_private(src_ip):
            auto_block_check(src_ip)

        if decision == "block":
            STATE.packets_blocked += 1
        else:
            STATE.packets_allowed += 1
            STATE.active_conns[src_ip].add(dst_port)

        STATE.recent_packets.appendleft({
            "t":      datetime.now().strftime("%H:%M:%S"),
            "src":    src_ip, "dst": dst_ip,
            "sport":  src_port, "dport": dst_port,
            "proto":  proto, "size": f"{pkt_len}B",
            "status": decision, "reason": reason, "flags": flags,
        })

import csv
import pathlib

REPORTS_DIR = pathlib.Path("reports")

def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)

def _report_filename(report_type: str, fmt: str) -> pathlib.Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return REPORTS_DIR / f"netguard_{report_type}_{ts}.{fmt}"

def run_report(report_type: str, fmt: str, filter_status: str = "all") -> str:
    ensure_reports_dir()
    path = _report_filename(report_type, fmt)
    with STATE.lock:
        pkts    = list(STATE.recent_packets)
        threats = list(STATE.threats)
    if filter_status != "all":
        pkts = [p for p in pkts if p.get("status") == filter_status]
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"generated_at": datetime.now().isoformat(), "data": pkts if report_type == "packets" else threats}, f, indent=2, ensure_ascii=False)
    else:
        with open(path, "w", newline="", encoding="utf-8") as f:
            if pkts:
                writer = csv.DictWriter(f, fieldnames=list(pkts[0].keys()), extrasaction="ignore")
                writer.writeheader()
                writer.writerows(pkts)
    return str(path)

def snapshot_traffic():
    with STATE.lock:
        STATE.traffic_history.append({
            "ts": time.time(), "in_bps": STATE.bytes_in,
            "out_bps": STATE.bytes_out, "blocked": STATE.packets_blocked,
            "pps": STATE.packets_total,
        })
        STATE.bytes_in  = 0
        STATE.bytes_out = 0

CLIENTS: set = set()

def build_state_message() -> dict:
    with STATE.lock:
        conns_count = sum(len(v) for v in STATE.active_conns.values())
        total       = max(STATE.packets_total, 1)
        proto_total = sum(STATE.proto_stats.values()) or 1
        top_ips     = sorted(STATE.ip_hit_counter.items(), key=lambda x: -x[1])[:10]
        return {
            "type":               "state",
            "ts":                 time.time(),
            "packets_total":      STATE.packets_total,
            "packets_blocked":    STATE.packets_blocked,
            "blocked_rate":       round(STATE.packets_blocked * 100 / total, 1),
            "active_conns":       conns_count,
            "threats_count":      len(STATE.threats),
            "recent_packets":     list(STATE.recent_packets)[:30],
            "threats":            list(STATE.threats)[:10],
            "traffic_history":    list(STATE.traffic_history),
            "proto_stats": [
                {"name": k, "count": v, "pct": round(v * 100 / proto_total, 1)}
                for k, v in sorted(STATE.proto_stats.items(), key=lambda x: -x[1])
            ],
            "blocked_ips":        list(BLOCKED_IPS)[:50],
            "rules": [
                {"key": k, "label": v["label"], "enabled": v["enabled"], "hits": v["hits"]}
                for k, v in RULES.items()
            ],
            "dpi_enabled":        CFG.dpi_enabled,
            "dpi_mask":           CFG.dpi_mask_sensitive,
            "auto_block_enabled": CFG.auto_block_enabled,
            "auto_block_hits":    CFG.auto_block_hits,
            "record_active":      STATE.record_active,
            "record_file":        STATE.record_file_path,
            "record_packets":     len(STATE.record_packets),
            "top_ips":            [{"ip": ip, "hits": h} for ip, h in top_ips],
            "dpi_alerts":         list(STATE.dpi_alerts)[:20],
            "suricata_enabled":   SURICATA_ENABLED,
            "suricata_rules":     SURICATA_LOADED,
            "suricata_alerts":    list(STATE.suricata_alerts)[:20],
            "geo_blocked_countries": list(GEO_BLOCKED_COUNTRIES),
            "geo_country_names":  GEO_COUNTRY_NAMES,
        }

async def ws_handler(websocket):
    global CLIENTS
    CLIENTS.add(websocket)
    log.info(f"[WS] Client connecté: {websocket.remote_address}")
    try:
        await websocket.send(json.dumps(build_state_message()))
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                await handle_ws_command(websocket, msg)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        log.debug(f"[WS] Client déconnecté: {e}")
    finally:
        CLIENTS.discard(websocket)

async def handle_ws_command(ws, msg: dict):
    global CLIENTS
    cmd = msg.get("cmd")

    if cmd == "get_state":
        await ws.send(json.dumps(build_state_message()))
    elif cmd == "toggle_rule":
        key = msg.get("rule")
        if key in RULES:
            RULES[key]["enabled"] = not RULES[key]["enabled"]
            await ws.send(json.dumps({"type": "rule_updated", "rule": key, "enabled": RULES[key]["enabled"]}))
    elif cmd == "block_ip":
        ip = msg.get("ip", "")
        reason = msg.get("reason", "Blocage manuel")
        if ip:
            block_ip_os(ip, reason)
            add_threat(ip, "Blocage manuel", reason, "med")
            await ws.send(json.dumps({"type": "ip_blocked", "ip": ip}))
    elif cmd == "unblock_ip":
        ip = msg.get("ip", "")
        if ip:
            unblock_ip_os(ip)
            await ws.send(json.dumps({"type": "ip_unblocked", "ip": ip}))
    elif cmd == "get_blocked_ips":
        await ws.send(json.dumps({"type": "blocked_ips", "ips": list(BLOCKED_IPS)}))
    elif cmd == "clear_threats":
        STATE.threats.clear()
        await ws.send(json.dumps({"type": "threats_cleared"}))
    elif cmd == "generate_report":
        rtype = msg.get("report_type", "full")
        fmt   = msg.get("format", "json")
        filt  = msg.get("filter", "all")
        try:
            filepath = run_report(rtype, fmt, filt)
            await ws.send(json.dumps({"type": "report_ready", "path": filepath}))
        except Exception as e:
            await ws.send(json.dumps({"type": "report_error", "error": str(e)}))
    elif cmd == "record_start":
        ok = record_start()
        await ws.send(json.dumps({"type": "record_started", "ok": ok, "path": STATE.record_file_path}))
    elif cmd == "record_stop":
        path = record_stop()
        await ws.send(json.dumps({"type": "record_stopped", "path": path}))
    elif cmd == "record_list":
        files = record_list()
        await ws.send(json.dumps({"type": "record_list", "files": files}))
    elif cmd == "toggle_dpi":
        CFG.dpi_enabled = not CFG.dpi_enabled
        await ws.send(json.dumps({"type": "dpi_toggled", "enabled": CFG.dpi_enabled}))
    elif cmd == "toggle_dpi_mask":
        CFG.dpi_mask_sensitive = not CFG.dpi_mask_sensitive
        await ws.send(json.dumps({"type": "dpi_mask_toggled", "enabled": CFG.dpi_mask_sensitive}))
    elif cmd == "get_dpi_alerts":
        await ws.send(json.dumps({"type": "dpi_alerts", "alerts": list(STATE.dpi_alerts)[:50]}))
    elif cmd == "set_auto_block_hits":
        val = int(msg.get("value", 10))
        CFG.auto_block_hits = max(1, min(50, val))
        await ws.send(json.dumps({"type": "auto_block_updated", "hits": CFG.auto_block_hits}))
    elif cmd == "toggle_auto_block":
        CFG.auto_block_enabled = not CFG.auto_block_enabled
        await ws.send(json.dumps({"type": "auto_block_toggled", "enabled": CFG.auto_block_enabled}))
    elif cmd == "update_param":
        key = msg.get("key", "")
        val = msg.get("value")
        if hasattr(CFG, key) and val is not None:
            try:
                setattr(CFG, key, type(getattr(CFG, key))(val))
                await ws.send(json.dumps({"type": "param_updated", "key": key}))
            except Exception as e:
                await ws.send(json.dumps({"type": "param_error", "error": str(e)}))

    # ── v1.6.0 — Suricata IDS ─────────────────────────────────────────
    elif cmd == "toggle_suricata":
        global SURICATA_ENABLED
        SURICATA_ENABLED = not SURICATA_ENABLED
        await ws.send(json.dumps({"type": "suricata_toggled", "enabled": SURICATA_ENABLED}))

    elif cmd == "get_suricata_stats":
        await ws.send(json.dumps({
            "type":    "suricata_stats",
            "enabled": SURICATA_ENABLED,
            "rules":   SURICATA_LOADED,
            "alerts":  list(STATE.suricata_alerts)[:50],
        }))

    elif cmd == "load_et_rules":
        ruleset = msg.get("ruleset", "et_scan")
        # Lancer en thread pour ne pas bloquer le WS
        def _load():
            result = load_et_rules_online(ruleset)
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type": "et_rules_loaded", "ruleset": ruleset, **result})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_load, daemon=True).start()
        await ws.send(json.dumps({"type": "et_rules_loading", "ruleset": ruleset}))

    # ── Géoblocage ────────────────────────────────────────────────────────
    elif cmd == "set_geo_countries":
        global GEO_BLOCKED_COUNTRIES
        countries = msg.get("countries", [])
        GEO_BLOCKED_COUNTRIES = set(countries)
        log.info(f"[GEO] Pays bloqués: {GEO_BLOCKED_COUNTRIES}")
        await ws.send(json.dumps({"type": "geo_updated", "countries": list(GEO_BLOCKED_COUNTRIES)}))
    global CLIENTS
    while True:
        await asyncio.sleep(1)
        snapshot_traffic()
        if CLIENTS:
            msg = json.dumps(build_state_message())
            dead = set()
            for ws in CLIENTS:
                try:
                    await ws.send(msg)
                except Exception:
                    dead.add(ws)
            CLIENTS = CLIENTS - dead

def auto_select_interface() -> str:
    if not HAS_SCAPY:
        return "eth0"
    ifaces = get_if_list()
    for pref in ["Wi-Fi", "wlan0", "wlan1", "eth0", "en0", "Ethernet"]:
        for iface in ifaces:
            if pref.lower() in iface.lower():
                return iface
    return ifaces[0] if ifaces else "eth0"

def start_capture(interface: str):
    if not HAS_SCAPY:
        log.error("scapy non disponible — mode DEMO activé")
        _run_demo_mode()
        return
    log.info(f"[CAPTURE] Démarrage sur: {interface}")
    try:
        sniff(iface=interface, prn=analyze_packet, store=False, filter="ip or arp")
    except PermissionError:
        log.error("ERREUR: Permissions insuffisantes.")
        sys.exit(1)
    except Exception as e:
        log.error(f"Erreur capture: {e}")
        _run_demo_mode()

def _run_demo_mode():
    import random
    log.info("[DEMO] Mode démonstration — trafic simulé")
    IPS = ["192.168.1.10","10.0.0.5","45.33.32.156","185.220.101.34",
           "91.108.4.1","77.88.55.66","203.0.113.1","198.51.100.5"]
    PROTOS = ["TCP","UDP","DNS","HTTPS","HTTP","SSH","RDP"]
    while True:
        time.sleep(0.08)
        with STATE.lock:
            src    = random.choice(IPS)
            proto  = random.choice(PROTOS)
            port   = {"TCP":80,"UDP":53,"DNS":53,"HTTPS":443,"HTTP":80,"SSH":22,"RDP":3389}[proto]
            is_bad = not is_private(src) and random.random() < 0.2
            status = "block" if is_bad else "allow"
            reason = random.choice(["Scan de ports","Brute Force SSH","IP blacklistée","","",""]) if is_bad else ""
            STATE.packets_total += 1
            STATE.proto_stats[proto] += 1
            if is_bad:
                STATE.packets_blocked += 1
                STATE.ip_hit_counter[src] += 1
            else:
                STATE.packets_allowed += 1
            STATE.bytes_in += random.randint(40, 1500)
            STATE.recent_packets.appendleft({
                "t": datetime.now().strftime("%H:%M:%S"),
                "src": src, "dst": "192.168.1.1",
                "sport": random.randint(1024,65535), "dport": port,
                "proto": proto, "size": f"{random.randint(40,1500)}B",
                "status": status, "reason": reason, "flags": "S" if proto=="TCP" else "",
            })
            if is_bad and random.random() < 0.3:
                STATE.threats.appendleft({
                    "id": int(time.time()*1000),
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src,
                    "type": reason or "Activité suspecte",
                    "description": f"Détecté depuis {src}",
                    "severity": random.choice(["high","med","low"]),
                    "blocked": True,
                })
            if random.random() < 0.05:
                STATE.dpi_alerts.appendleft({
                    "ts": datetime.now().strftime("%H:%M:%S"),
                    "src": src,
                    "type": random.choice(["attack","sensitive"]),
                    "detail": random.choice(["SQL Injection","XSS","password","cookie"]),
                    "masked": random.choice([True, False]),
                })

async def main_async(interface: str):
    threading.Thread(target=start_capture, args=(interface,), daemon=True).start()
    log.info(f"[WS] Serveur WebSocket sur ws://localhost:{CFG.ws_port}")
    if HAS_WS:
        async with websockets.serve(ws_handler, "localhost", CFG.ws_port, reuse_address=True):
            await broadcast_state()
    else:
        while True:
            await asyncio.sleep(1)
            snapshot_traffic()

def main():
    parser = argparse.ArgumentParser(description="NetGuard Pro — Surveillance réseau")
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--port",      type=int, default=8765)
    parser.add_argument("--no-block",  action="store_true")
    parser.add_argument("--demo",      action="store_true")
    args = parser.parse_args()

    CFG.ws_port   = args.port
    CFG.can_block = not args.no_block

    if args.demo:
        global HAS_SCAPY
        HAS_SCAPY = False

    interface = args.interface
    if interface == "auto":
        interface = auto_select_interface()
        log.info(f"[AUTO] Interface sélectionnée: {interface}")

    # Créer les dossiers nécessaires
    os.makedirs(CFG.record_dir, exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    print("""
╔══════════════════════════════════════════════╗
║      NetGuard Pro v1.6.0 — Démarrage        ║
╠══════════════════════════════════════════════╣
║  DPI + Record + Auto-block + Suricata IDS   ║
║  Dashboard: netguard_dashboard.html         ║
╚══════════════════════════════════════════════╝
""")
    log.info("[MODE] Protection active" if CFG.can_block else "[MODE] Surveillance uniquement")
    try:
        asyncio.run(main_async(interface))
    except KeyboardInterrupt:
        log.info("Arrêt de NetGuard Pro.")

if __name__ == "__main__":
    main()
