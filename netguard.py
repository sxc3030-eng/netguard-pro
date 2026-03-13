"""
NetGuard Pro - Moteur de surveillance réseau
Capture, analyse et bloque les paquets en temps réel
Auteur: NetGuard Pro
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
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from typing import Optional
import os
import sys

# ─── Dépendances optionnelles ───────────────────────────────────────────────
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

# ─── Configuration ────────────────────────────────────────────────────────────
@dataclass
class Config:
    interface:       str   = "auto"
    ws_port:         int   = 8765
    can_block:       bool  = True
    log_file:        str   = "netguard.log"
    max_packets_log: int   = 10_000
    # Seuils de détection
    port_scan_threshold:    int = 15    # ports différents en N secondes
    port_scan_window:       int = 10    # secondes
    brute_force_threshold:  int = 8     # tentatives en N secondes
    brute_force_window:     int = 30
    syn_flood_threshold:    int = 200   # SYN/sec depuis une même IP
    syn_flood_window:       int = 5
    dns_tunnel_threshold:   int = 50    # requêtes DNS/sec
    # IPs et réseaux toujours autorisés (LAN)
    whitelist: list = field(default_factory=lambda: [
        "127.0.0.1", "::1",
        "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"
    ])
    # Ports SSH/RDP autorisés uniquement depuis LAN
    sensitive_ports: list = field(default_factory=lambda: [22, 3389, 5900, 23])
    # Ports toujours bloqués (depuis externe)
    always_block_ports: list = field(default_factory=lambda: [135, 137, 138, 139, 445, 1433, 3306])

CFG = Config()

# ─── Règles utilisateur ────────────────────────────────────────────────────
RULES = {
    # Détection dynamique
    "block_port_scan":      {"enabled": True,  "label": "Bloquer scan de ports",          "hits": 0, "cat": "Détection"},
    "block_brute_force":    {"enabled": True,  "label": "Bloquer Brute Force SSH/RDP",    "hits": 0, "cat": "Détection"},
    "block_syn_flood":      {"enabled": True,  "label": "Bloquer SYN Flood",              "hits": 0, "cat": "Détection"},
    "block_icmp_flood":     {"enabled": True,  "label": "Bloquer ICMP Flood",             "hits": 0, "cat": "Détection"},
    "detect_http_scan":     {"enabled": True,  "label": "Détecter scanners HTTP/vuln",    "hits": 0, "cat": "Détection"},
    "detect_arp_spoof":     {"enabled": True,  "label": "Détecter ARP Spoofing (LAN)",    "hits": 0, "cat": "Détection"},
    "detect_dns_tunnel":    {"enabled": True,  "label": "Détecter DNS Tunneling",         "hits": 0, "cat": "Détection"},
    "detect_malicious_dns": {"enabled": True,  "label": "Détecter domaines malveillants", "hits": 0, "cat": "Détection"},
    # Ports
    "block_ssh_external":   {"enabled": True,  "label": "Bloquer SSH externe (port 22)",  "hits": 0, "cat": "Ports"},
    "block_rdp_public":     {"enabled": True,  "label": "Bloquer RDP public (port 3389)", "hits": 0, "cat": "Ports"},
    "block_p2p":            {"enabled": True,  "label": "Bloquer P2P/BitTorrent",         "hits": 0, "cat": "Ports"},
    "block_smb":            {"enabled": True,  "label": "Bloquer SMB externe (445/139)",  "hits": 0, "cat": "Ports"},
    "block_telnet":         {"enabled": True,  "label": "Bloquer Telnet (port 23)",       "hits": 0, "cat": "Ports"},
    "block_ftp":            {"enabled": False, "label": "Bloquer FTP non-sécurisé (21)",  "hits": 0, "cat": "Ports"},
    # Listes noires
    "block_tor":            {"enabled": True,  "label": "Bloquer noeuds Tor",             "hits": 0, "cat": "Blacklist"},
    "block_vpn_known":      {"enabled": True,  "label": "Bloquer VPN connus",             "hits": 0, "cat": "Blacklist"},
    "block_proxy_public":   {"enabled": True,  "label": "Bloquer proxies publics",        "hits": 0, "cat": "Blacklist"},
    # Géoblocage
    "geo_block":            {"enabled": False, "label": "Géoblocage par pays",            "hits": 0, "cat": "Géo"},
}

# ─── Paramètres de détection (modifiables depuis le dashboard) ─────────────
DETECTION_PARAMS = {
    "port_scan_threshold":   {"value": 15,  "label": "Scan de ports — nb de ports",     "min": 5,   "max": 100,  "unit": "ports"},
    "port_scan_window":      {"value": 10,  "label": "Scan de ports — fenêtre",          "min": 5,   "max": 60,   "unit": "sec"},
    "brute_force_threshold": {"value": 8,   "label": "Brute Force — nb tentatives",      "min": 3,   "max": 50,   "unit": "tentatives"},
    "brute_force_window":    {"value": 30,  "label": "Brute Force — fenêtre",            "min": 10,  "max": 120,  "unit": "sec"},
    "syn_flood_threshold":   {"value": 200, "label": "SYN Flood — paquets/fenêtre",      "min": 50,  "max": 1000, "unit": "paquets"},
    "syn_flood_window":      {"value": 5,   "label": "SYN Flood — fenêtre",              "min": 1,   "max": 30,   "unit": "sec"},
    "icmp_flood_threshold":  {"value": 100, "label": "ICMP Flood — paquets/fenêtre",     "min": 20,  "max": 500,  "unit": "paquets"},
    "icmp_flood_window":     {"value": 5,   "label": "ICMP Flood — fenêtre",             "min": 1,   "max": 30,   "unit": "sec"},
    "dns_tunnel_threshold":  {"value": 50,  "label": "DNS Tunneling — requêtes/fenêtre", "min": 10,  "max": 200,  "unit": "requêtes"},
    "http_scan_threshold":   {"value": 30,  "label": "Scanner HTTP — requêtes/fenêtre",  "min": 10,  "max": 200,  "unit": "requêtes"},
}

# ─── Géoblocage ────────────────────────────────────────────────────────────
GEO_BLOCKED_COUNTRIES: set = set()

GEO_IP_RANGES = {
    "RU": ["5.8.0.0/16","5.44.0.0/22","37.9.0.0/16","46.8.0.0/16","77.37.128.0/17",
           "80.73.0.0/18","81.162.0.0/16","82.138.0.0/17","83.149.0.0/17","84.201.0.0/16",
           "85.90.0.0/15","87.226.128.0/17","89.111.0.0/18","91.108.4.0/22","91.227.64.0/18",
           "92.53.0.0/18","93.153.128.0/17","94.25.0.0/16","95.165.0.0/16","109.86.0.0/15",
           "176.14.0.0/16","176.57.0.0/17","178.140.0.0/14","185.71.76.0/22",
           "193.232.0.0/14","194.8.0.0/15","195.2.0.0/16","212.42.0.0/17","213.24.0.0/14"],
    "CN": ["1.0.1.0/24","1.0.2.0/23","27.0.0.0/13","36.0.0.0/11","39.0.0.0/8",
           "42.0.0.0/8","49.0.0.0/8","58.0.0.0/7","60.0.0.0/8","61.0.0.0/8",
           "101.0.0.0/8","106.0.0.0/8","110.0.0.0/7","112.0.0.0/7","114.0.0.0/8",
           "115.0.0.0/8","116.0.0.0/6","120.0.0.0/6","124.0.0.0/7","163.0.0.0/8",
           "171.0.0.0/8","175.0.0.0/8","180.0.0.0/6","182.0.0.0/7","183.0.0.0/8",
           "202.0.0.0/7","210.0.0.0/7","218.0.0.0/7","220.0.0.0/6","223.0.0.0/8"],
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
    "BR": ["177.0.0.0/8","179.0.0.0/8","186.192.0.0/11","189.0.0.0/8",
           "200.128.0.0/9","201.0.0.0/8"],
    "NG": ["41.58.0.0/16","41.184.0.0/14","105.112.0.0/12","154.120.0.0/13",
           "197.210.0.0/15","197.242.0.0/15"],
    "IN": ["1.6.0.0/15","14.96.0.0/11","27.4.0.0/14","43.224.0.0/11","45.112.0.0/12",
           "49.32.0.0/12","59.88.0.0/13","59.96.0.0/12","103.0.0.0/8","106.64.0.0/10",
           "115.240.0.0/13","117.192.0.0/11","119.224.0.0/11","122.160.0.0/11",
           "123.136.0.0/13","124.120.0.0/13","180.64.0.0/12","182.64.0.0/10",
           "202.56.0.0/16","210.212.0.0/14"],
    "US": ["3.0.0.0/8","4.0.0.0/8","8.0.0.0/8","12.0.0.0/8","13.0.0.0/8",
           "15.0.0.0/8","16.0.0.0/8","17.0.0.0/8","18.0.0.0/8","20.0.0.0/8",
           "23.0.0.0/8","24.0.0.0/8","34.0.0.0/8","35.0.0.0/8","40.0.0.0/8",
           "44.0.0.0/8","45.0.0.0/8","47.0.0.0/8","50.0.0.0/8","52.0.0.0/8",
           "54.0.0.0/8","63.0.0.0/8","64.0.0.0/8","65.0.0.0/8","66.0.0.0/8",
           "67.0.0.0/8","68.0.0.0/8","98.0.0.0/8","104.0.0.0/8","107.0.0.0/8"],
    "DE": ["5.1.0.0/17","5.56.0.0/14","5.180.0.0/14","5.252.0.0/14","31.10.0.0/14",
           "46.4.0.0/14","46.231.0.0/16","78.42.0.0/15","78.94.0.0/15","80.64.0.0/13",
           "80.154.0.0/15","81.169.0.0/16","82.113.0.0/16","84.44.0.0/14","85.14.0.0/15",
           "85.119.0.0/17","87.77.0.0/16","89.0.0.0/16","91.65.0.0/16","94.130.0.0/15",
           "213.160.0.0/14"],
    "FR": ["2.0.0.0/11","2.14.0.0/15","5.39.0.0/17","37.187.0.0/16","46.105.0.0/16",
           "51.77.0.0/16","51.178.0.0/15","77.136.0.0/13","78.192.0.0/11","82.64.0.0/11",
           "83.200.0.0/13","86.192.0.0/11","88.120.0.0/13","90.0.0.0/11","90.48.0.0/13",
           "109.0.0.0/12","176.139.0.0/16","178.116.0.0/14","185.15.0.0/16"],
    "NL": ["2.56.0.0/14","5.57.64.0/18","31.3.0.0/16","31.6.0.0/16","37.19.0.0/16",
           "45.14.0.0/16","46.19.0.0/16","77.243.0.0/16","80.65.0.0/17","80.100.0.0/14",
           "82.94.0.0/15","84.22.0.0/15","85.17.0.0/16","87.213.0.0/16","89.188.0.0/15",
           "91.194.0.0/15","94.75.0.0/16","95.211.0.0/16","185.220.0.0/16"],
}

GEO_COUNTRY_NAMES = {
    "RU": "Russie", "CN": "Chine", "KP": "Corée du Nord", "IR": "Iran",
    "KR": "Corée du Sud", "BR": "Brésil", "NG": "Nigeria", "IN": "Inde",
    "US": "États-Unis", "DE": "Allemagne", "FR": "France", "NL": "Pays-Bas",
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

# ─── Listes noires ─────────────────────────────────────────────────────────
BLOCKED_IPS:  set = set()
BLOCKED_NETS: list = []

KNOWN_BAD_RANGES = {
    "tor":   ["185.220.0.0/16","185.220.100.0/22","162.247.74.0/24",
              "204.8.96.0/22","199.87.154.0/24","185.100.86.0/23"],
    "vpn":   ["104.200.16.0/20","23.19.0.0/16","149.154.0.0/16",
              "91.108.4.0/22","149.154.160.0/22","185.76.151.0/24"],
    "proxy": ["185.56.80.0/22","91.219.236.0/22","194.165.16.0/23",
              "185.142.236.0/22","46.166.0.0/17"],
}

MALICIOUS_DOMAINS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    "duckdns.org", "no-ip.com", "ddns.net",
    "ngrok.io", "pagekite.me", ".onion",
}

P2P_PORTS = set(range(6881, 6890)) | {51413, 1337, 2710, 6969}

HTTP_SCANNER_AGENTS = {
    "masscan", "zgrab", "nmap", "nikto", "sqlmap", "dirbuster",
    "gobuster", "wfuzz", "burpsuite", "acunetix", "nessus",
    "openvas", "w3af", "havij", "sqlninja", "hydra",
}

# ─── État global ──────────────────────────────────────────────────────────
class NetState:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets_total    = 0
        self.packets_blocked  = 0
        self.packets_allowed  = 0
        self.bytes_in         = 0
        self.bytes_out        = 0
        self.active_conns     = defaultdict(set)   # ip -> {ports}
        self.threats          = deque(maxlen=100)
        self.recent_packets   = deque(maxlen=500)
        self.geo_hits         = defaultdict(int)
        self.proto_stats      = defaultdict(int)
        self.traffic_history  = deque(maxlen=60)   # 1 point/sec
        # Fenêtres glissantes pour détection
        self._port_scan_tracker    = defaultdict(list)
        self._brute_force_tracker  = defaultdict(list)
        self._syn_flood_tracker    = defaultdict(list)
        self._dns_tracker          = defaultdict(list)
        self._icmp_tracker         = defaultdict(list)
        self._http_tracker         = defaultdict(list)
        self._arp_table            = {}               # ip -> mac (ARP spoof detection)

STATE = NetState()

# ─── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(CFG.log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("netguard")

# ─── Helpers réseau ────────────────────────────────────────────────────────
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

def is_in_bad_range(ip: str, category: str = None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        cats = [category] if category else list(KNOWN_BAD_RANGES.keys())
        for cat in cats:
            for net_str in KNOWN_BAD_RANGES.get(cat, []):
                try:
                    if a in ipaddress.ip_network(net_str, strict=False):
                        return True
                except ValueError:
                    pass
    except ValueError:
        pass
    return False

def get_protocol_name(pkt) -> str:
    if HAS_SCAPY:
        if pkt.haslayer(DNS):   return "DNS"
        if pkt.haslayer(TCP):
            dp = pkt[TCP].dport
            if dp == 443: return "HTTPS"
            if dp == 80:  return "HTTP"
            if dp == 22:  return "SSH"
            if dp == 21:  return "FTP"
            if dp == 25:  return "SMTP"
            if dp == 3389:return "RDP"
            return "TCP"
        if pkt.haslayer(UDP):   return "UDP"
        if pkt.haslayer(ICMP):  return "ICMP"
        if pkt.haslayer(ARP):   return "ARP"
    return "OTHER"

# ─── Blocage OS ────────────────────────────────────────────────────────────
def block_ip_os(ip: str, reason: str):
    """Bloque une IP au niveau du pare-feu OS (iptables / netsh)"""
    if ip in BLOCKED_IPS:
        return
    BLOCKED_IPS.add(ip)
    log.warning(f"[BLOCK] {ip} — {reason}")

    if not CFG.can_block:
        log.info(f"[DRY-RUN] Blocage simulé pour {ip}")
        return

    try:
        if IS_LINUX:
            os.system(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null")
            os.system(f"iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            os.system(
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip} enable=yes'
            )
    except Exception as e:
        log.error(f"Erreur blocage OS pour {ip}: {e}")

def unblock_ip_os(ip: str):
    """Débloque une IP"""
    BLOCKED_IPS.discard(ip)
    try:
        if IS_LINUX:
            os.system(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
        elif IS_WINDOWS:
            rule_name = f"NetGuard_Block_{ip.replace('.','_')}"
            os.system(
                f'netsh advfirewall firewall delete rule name="{rule_name}"'
            )
    except Exception as e:
        log.error(f"Erreur déblocage OS pour {ip}: {e}")

# ─── Moteur de détection ──────────────────────────────────────────────────
def add_threat(src_ip: str, threat_type: str, description: str, severity: str, rule_key: str = None):
    threat = {
        "id":          int(time.time() * 1000),
        "timestamp":   datetime.now().isoformat(),
        "src_ip":      src_ip,
        "type":        threat_type,
        "description": description,
        "severity":    severity,  # high / med / low
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
    STATE._port_scan_tracker[src_ip] = [
        (t, p) for t, p in tracker if t > now - CFG.port_scan_window
    ]
    unique_ports = len({p for _, p in STATE._port_scan_tracker[src_ip]})
    if unique_ports >= CFG.port_scan_threshold:
        return f"Scan de {unique_ports} ports en {CFG.port_scan_window}s"
    return None

def detect_brute_force(src_ip: str, dst_port: int, is_syn: bool) -> Optional[str]:
    if not RULES["block_brute_force"]["enabled"]:
        return None
    if dst_port not in CFG.sensitive_ports:
        return None
    if not is_syn:
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
    if not RULES["block_syn_flood"]["enabled"]:
        return None
    if not is_syn:
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

def detect_icmp_flood(src_ip: str) -> Optional[str]:
    if not RULES["block_icmp_flood"]["enabled"]:
        return None
    tracker = STATE._icmp_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    window = DETECTION_PARAMS["icmp_flood_window"]["value"]
    threshold = DETECTION_PARAMS["icmp_flood_threshold"]["value"]
    STATE._icmp_tracker[src_ip] = _clean_window(tracker, window)
    count = len(STATE._icmp_tracker[src_ip])
    if count >= threshold:
        return f"ICMP Flood: {count} paquets/{window}s"
    return None

def detect_http_scanner(src_ip: str, raw_payload: str) -> Optional[str]:
    if not RULES["detect_http_scan"]["enabled"]:
        return None
    payload_lower = raw_payload.lower()
    for agent in HTTP_SCANNER_AGENTS:
        if agent in payload_lower:
            return f"Scanner HTTP détecté: {agent}"
    # Detect rapid HTTP requests
    tracker = STATE._http_tracker[src_ip]
    now = time.time()
    tracker.append(now)
    window = 10
    threshold = DETECTION_PARAMS["http_scan_threshold"]["value"]
    STATE._http_tracker[src_ip] = _clean_window(tracker, window)
    count = len(STATE._http_tracker[src_ip])
    if count >= threshold:
        return f"Scan HTTP rapide: {count} requêtes/{window}s"
    return None

def detect_arp_spoof(pkt) -> Optional[str]:
    if not RULES["detect_arp_spoof"]["enabled"]:
        return None
    if not HAS_SCAPY or not pkt.haslayer(ARP):
        return None
    arp = pkt[ARP]
    if arp.op != 2:  # ARP reply only
        return None
    src_ip  = arp.psrc
    src_mac = arp.hwsrc
    if src_ip in STATE._arp_table:
        known_mac = STATE._arp_table[src_ip]
        if known_mac != src_mac:
            return f"ARP Spoofing: {src_ip} change MAC {known_mac} -> {src_mac}"
    STATE._arp_table[src_ip] = src_mac
    return None

def detect_malicious_domain(pkt) -> Optional[str]:
    if not RULES["detect_malicious_dns"]["enabled"]:
        return None
    if not HAS_SCAPY or not pkt.haslayer(DNS):
        return None
    try:
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd:  # DNS query
            qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            for bad in MALICIOUS_DOMAINS:
                if qname.endswith(bad):
                    return f"Domaine malveillant: {qname}"
    except Exception:
        pass
    return None

# ─── Analyse d'un paquet ──────────────────────────────────────────────────
def analyze_packet(pkt):
    if not HAS_SCAPY:
        return
    if not pkt.haslayer(IP):
        return

    src_ip  = pkt[IP].src
    dst_ip  = pkt[IP].dst
    pkt_len = len(pkt)
    proto   = get_protocol_name(pkt)
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

    decision  = "allow"
    reason    = ""
    country   = None

    with STATE.lock:
        STATE.packets_total += 1
        STATE.proto_stats[proto] += 1

        if is_private(dst_ip):
            STATE.bytes_in += pkt_len
        else:
            STATE.bytes_out += pkt_len

        # ── ARP spoof (LAN, avant IP check) ──────────────────────────────
        if HAS_SCAPY and pkt.haslayer(ARP):
            arp_reason = detect_arp_spoof(pkt)
            if arp_reason:
                add_threat(pkt[ARP].psrc, "ARP Spoofing", arp_reason, "high", "detect_arp_spoof")

        if not pkt.haslayer(IP) if HAS_SCAPY else False:
            return

        # ── 1. IP déjà bloquée ───────────────────────────────────────────
        if src_ip in BLOCKED_IPS:
            decision = "block"
            reason   = "IP blacklistée"

        # ── 2. Géoblocage ────────────────────────────────────────────────
        elif RULES["geo_block"]["enabled"] and not is_private(src_ip):
            country = get_country(src_ip)
            if country and country in GEO_BLOCKED_COUNTRIES:
                decision = "block"
                reason   = f"Géoblocage: {GEO_COUNTRY_NAMES.get(country, country)}"
                RULES["geo_block"]["hits"] += 1
                block_ip_os(src_ip, reason)

        # ── 3. Tor ───────────────────────────────────────────────────────
        elif RULES["block_tor"]["enabled"] and is_in_bad_range(src_ip, "tor"):
            decision = "block"
            reason   = "Noeud Tor détecté"
            RULES["block_tor"]["hits"] += 1
            block_ip_os(src_ip, reason)

        # ── 4. VPN connu ─────────────────────────────────────────────────
        elif RULES["block_vpn_known"]["enabled"] and is_in_bad_range(src_ip, "vpn"):
            decision = "block"
            reason   = "VPN connu"
            RULES["block_vpn_known"]["hits"] += 1
            block_ip_os(src_ip, reason)

        # ── 5. Proxy public ──────────────────────────────────────────────
        elif RULES["block_proxy_public"]["enabled"] and is_in_bad_range(src_ip, "proxy"):
            decision = "block"
            reason   = "Proxy public"
            RULES["block_proxy_public"]["hits"] += 1
            block_ip_os(src_ip, reason)

        # ── 6. Ports sensibles depuis externe ────────────────────────────
        elif not is_private(src_ip):
            if dst_port == 22 and RULES["block_ssh_external"]["enabled"]:
                decision = "block"
                reason   = "SSH depuis IP externe"
                RULES["block_ssh_external"]["hits"] += 1
            elif dst_port == 3389 and RULES["block_rdp_public"]["enabled"]:
                decision = "block"
                reason   = "RDP depuis IP externe"
                RULES["block_rdp_public"]["hits"] += 1
            elif dst_port in {445, 139} and RULES["block_smb"]["enabled"]:
                decision = "block"
                reason   = "SMB depuis IP externe"
                RULES["block_smb"]["hits"] += 1
            elif dst_port == 23 and RULES["block_telnet"]["enabled"]:
                decision = "block"
                reason   = "Telnet depuis IP externe"
                RULES["block_telnet"]["hits"] += 1
            elif dst_port == 21 and RULES["block_ftp"]["enabled"]:
                decision = "block"
                reason   = "FTP non-sécurisé"
                RULES["block_ftp"]["hits"] += 1

        # ── 7. P2P ───────────────────────────────────────────────────────
        if decision == "allow" and RULES["block_p2p"]["enabled"]:
            if dst_port in P2P_PORTS or src_port in P2P_PORTS:
                decision = "block"
                reason   = "Trafic P2P/BitTorrent"
                RULES["block_p2p"]["hits"] += 1

        # ── 8. Détections dynamiques (IPs externes seulement) ────────────
        if decision == "allow" and not is_private(src_ip):
            # ICMP flood
            if HAS_SCAPY and pkt.haslayer(ICMP):
                icmp_r = detect_icmp_flood(src_ip)
                if icmp_r:
                    decision = "block"
                    reason   = icmp_r
                    add_threat(src_ip, "ICMP Flood", icmp_r, "high", "block_icmp_flood")
                    block_ip_os(src_ip, icmp_r)

            # Port scan
            if decision == "allow" and dst_port:
                scan_r = detect_port_scan(src_ip, dst_port)
                if scan_r:
                    decision = "block"
                    reason   = scan_r
                    add_threat(src_ip, "Scan de ports", scan_r, "high", "block_port_scan")
                    block_ip_os(src_ip, scan_r)

            # Brute force
            if decision == "allow":
                bf_r = detect_brute_force(src_ip, dst_port, is_syn)
                if bf_r:
                    decision = "block"
                    reason   = bf_r
                    add_threat(src_ip, "Brute Force", bf_r, "high", "block_brute_force")
                    block_ip_os(src_ip, bf_r)

            # SYN flood
            if decision == "allow":
                syn_r = detect_syn_flood(src_ip, is_syn)
                if syn_r:
                    decision = "block"
                    reason   = syn_r
                    add_threat(src_ip, "SYN Flood", syn_r, "high", "block_syn_flood")
                    block_ip_os(src_ip, syn_r)

            # HTTP scanner
            if decision == "allow" and HAS_SCAPY and pkt.haslayer(Raw) and dst_port in {80,8080,8000,443}:
                try:
                    payload = pkt[Raw].load.decode("utf-8","ignore")
                    http_r = detect_http_scanner(src_ip, payload)
                    if http_r:
                        decision = "warn"
                        reason   = http_r
                        add_threat(src_ip, "Scanner HTTP", http_r, "med", "detect_http_scan")
                except Exception:
                    pass

        # ── 9. DNS checks (tous) ─────────────────────────────────────────
        if decision == "allow" and HAS_SCAPY and pkt.haslayer(DNS):
            # Domaine malveillant
            mal_r = detect_malicious_domain(pkt)
            if mal_r:
                decision = "warn"
                reason   = mal_r
                add_threat(src_ip, "Domaine malveillant", mal_r, "med", "detect_malicious_dns")

            # DNS tunneling
            if decision == "allow":
                dns_r = detect_dns_tunneling(src_ip)
                if dns_r:
                    decision = "warn"
                    reason   = dns_r
                    add_threat(src_ip, "DNS Tunneling", dns_r, "med", "detect_dns_tunnel")

        # ── Mise à jour des stats ─────────────────────────────────────────
        if decision == "block":
            STATE.packets_blocked += 1
        else:
            STATE.packets_allowed += 1
            STATE.active_conns[src_ip].add(dst_port)

        # Enregistrement du paquet
        entry = {
            "t":       datetime.now().strftime("%H:%M:%S"),
            "src":     src_ip,
            "dst":     dst_ip,
            "sport":   src_port,
            "dport":   dst_port,
            "proto":   proto,
            "size":    f"{pkt_len}B",
            "status":  decision,
            "reason":  reason,
            "flags":   flags,
        }
        STATE.recent_packets.appendleft(entry)

# ─── Système de rapports ─────────────────────────────────────────────────
import csv
import pathlib

REPORTS_DIR = pathlib.Path("reports")

def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)

def _report_filename(report_type: str, fmt: str) -> pathlib.Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return REPORTS_DIR / f"netguard_{report_type}_{ts}.{fmt}"

# ── Rapport paquets ───────────────────────────────────────────────────────
def generate_packets_csv(filter_status: str = "all") -> str:
    ensure_reports_dir()
    path = _report_filename("packets", "csv")
    with STATE.lock:
        pkts = list(STATE.recent_packets)
    if filter_status != "all":
        pkts = [p for p in pkts if p.get("status") == filter_status]
    fields = ["t", "src", "dst", "sport", "dport", "proto", "flags", "size", "status", "reason"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(pkts)
    log.info(f"[RAPPORT] Paquets CSV → {path}")
    return str(path)

def generate_packets_json(filter_status: str = "all") -> str:
    ensure_reports_dir()
    path = _report_filename("packets", "json")
    with STATE.lock:
        pkts = list(STATE.recent_packets)
    if filter_status != "all":
        pkts = [p for p in pkts if p.get("status") == filter_status]
    report = {
        "generated_at":  datetime.now().isoformat(),
        "filter":        filter_status,
        "total_packets": len(pkts),
        "packets":       pkts,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info(f"[RAPPORT] Paquets JSON → {path}")
    return str(path)

# ── Rapport menaces ───────────────────────────────────────────────────────
def generate_threats_csv() -> str:
    ensure_reports_dir()
    path = _report_filename("threats", "csv")
    with STATE.lock:
        threats = list(STATE.threats)
    fields = ["timestamp", "src_ip", "type", "description", "severity", "blocked"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(threats)
    log.info(f"[RAPPORT] Menaces CSV → {path}")
    return str(path)

def generate_threats_json() -> str:
    ensure_reports_dir()
    path = _report_filename("threats", "json")
    with STATE.lock:
        threats = list(STATE.threats)
    # Statistiques par type et sévérité
    by_type = defaultdict(int)
    by_sev  = defaultdict(int)
    for t in threats:
        by_type[t.get("type", "?")] += 1
        by_sev[t.get("severity", "?")] += 1
    report = {
        "generated_at":    datetime.now().isoformat(),
        "total_threats":   len(threats),
        "by_severity":     dict(by_sev),
        "by_type":         dict(by_type),
        "threats":         threats,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info(f"[RAPPORT] Menaces JSON → {path}")
    return str(path)

# ── Rapport IPs bloquées ──────────────────────────────────────────────────
def generate_blocked_ips_csv() -> str:
    ensure_reports_dir()
    path = _report_filename("blocked_ips", "csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip_address", "blocked_at"])
        for ip in sorted(BLOCKED_IPS):
            writer.writerow([ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    log.info(f"[RAPPORT] IPs bloquées CSV → {path}")
    return str(path)

def generate_blocked_ips_json() -> str:
    ensure_reports_dir()
    path = _report_filename("blocked_ips", "json")
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_blocked": len(BLOCKED_IPS),
        "blocked_ips":  sorted(list(BLOCKED_IPS)),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info(f"[RAPPORT] IPs bloquées JSON → {path}")
    return str(path)

# ── Rapport complet TXT ───────────────────────────────────────────────────
def generate_full_report_txt() -> str:
    ensure_reports_dir()
    path = _report_filename("full_report", "txt")
    now = datetime.now()
    with STATE.lock:
        pkts    = list(STATE.recent_packets)
        threats = list(STATE.threats)
        total   = STATE.packets_total
        blocked = STATE.packets_blocked

    blocked_pkts  = [p for p in pkts if p.get("status") == "block"]
    warn_pkts     = [p for p in pkts if p.get("status") == "warn"]

    # Top IPs suspectes
    ip_counts = defaultdict(int)
    for p in blocked_pkts:
        ip_counts[p.get("src", "?")] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]

    # Top types de menaces
    threat_counts = defaultdict(int)
    for t in threats:
        threat_counts[t.get("type", "?")] += 1

    lines = [
        "=" * 60,
        "  NETGUARD PRO — RAPPORT COMPLET",
        f"  Généré le : {now.strftime('%Y-%m-%d à %H:%M:%S')}",
        f"  Par       : sxc3030-eng",
        "=" * 60,
        "",
        "── RÉSUMÉ GÉNÉRAL ───────────────────────────────────────",
        f"  Paquets analysés   : {total:,}",
        f"  Paquets bloqués    : {blocked:,}  ({round(blocked*100/max(total,1),1)}%)",
        f"  Paquets en alerte  : {len(warn_pkts):,}",
        f"  Menaces détectées  : {len(threats):,}",
        f"  IPs bloquées       : {len(BLOCKED_IPS):,}",
        "",
        "── TOP 10 IPs SUSPECTES ─────────────────────────────────",
    ]
    if top_ips:
        for ip, count in top_ips:
            lines.append(f"  {ip:<20} {count:>6} paquets bloqués")
    else:
        lines.append("  Aucune IP suspecte détectée")

    lines += [
        "",
        "── TYPES DE MENACES ─────────────────────────────────────",
    ]
    if threat_counts:
        for ttype, count in sorted(threat_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {ttype:<30} {count:>4} détections")
    else:
        lines.append("  Aucune menace détectée")

    lines += [
        "",
        "── IPs BLOQUÉES ─────────────────────────────────────────",
    ]
    if BLOCKED_IPS:
        for ip in sorted(BLOCKED_IPS):
            lines.append(f"  {ip}")
    else:
        lines.append("  Aucune IP bloquée")

    lines += [
        "",
        "── DERNIERS PAQUETS BLOQUÉS (max 20) ────────────────────",
        f"  {'Heure':<10} {'Source IP':<20} {'Dest':<16} {'Port':<6} {'Proto':<6} {'Raison'}",
        "  " + "-" * 78,
    ]
    for p in blocked_pkts[:20]:
        lines.append(
            f"  {p.get('t',''):<10} {p.get('src',''):<20} {p.get('dst',''):<16} "
            f"{str(p.get('dport','')):<6} {p.get('proto',''):<6} {p.get('reason','')}"
        )

    lines += [
        "",
        "── DERNIÈRES MENACES (max 20) ───────────────────────────",
        f"  {'Timestamp':<22} {'IP':<18} {'Type':<25} {'Sévérité'}",
        "  " + "-" * 78,
    ]
    for t in threats[:20]:
        ts = t.get("timestamp", "")[:19].replace("T", " ")
        lines.append(
            f"  {ts:<22} {t.get('src_ip',''):<18} "
            f"{t.get('type',''):<25} {t.get('severity','').upper()}"
        )

    lines += [
        "",
        "── RÈGLES ACTIVES ───────────────────────────────────────",
    ]
    for key, rule in RULES.items():
        status = "ON " if rule["enabled"] else "OFF"
        lines.append(f"  [{status}] {rule['label']:<35} {rule['hits']:>4} déclenchements")

    lines += [
        "",
        "=" * 60,
        "  Fin du rapport — NetGuard Pro",
        "=" * 60,
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info(f"[RAPPORT] Rapport complet TXT → {path}")
    return str(path)

# ── Rapport complet JSON (tout en un) ─────────────────────────────────────
def generate_full_report_json() -> str:
    ensure_reports_dir()
    path = _report_filename("full_report", "json")
    with STATE.lock:
        pkts    = list(STATE.recent_packets)
        threats = list(STATE.threats)
    report = {
        "generated_at":    datetime.now().isoformat(),
        "author":          "sxc3030-eng",
        "summary": {
            "packets_total":   STATE.packets_total,
            "packets_blocked": STATE.packets_blocked,
            "packets_allowed": STATE.packets_allowed,
            "blocked_rate":    round(STATE.packets_blocked * 100 / max(STATE.packets_total, 1), 1),
            "threats_total":   len(threats),
            "ips_blocked":     len(BLOCKED_IPS),
        },
        "blocked_ips":     sorted(list(BLOCKED_IPS)),
        "threats":         threats,
        "packets_blocked": [p for p in pkts if p.get("status") == "block"],
        "packets_warned":  [p for p in pkts if p.get("status") == "warn"],
        "rules":           {k: v for k, v in RULES.items()},
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info(f"[RAPPORT] Rapport complet JSON → {path}")
    return str(path)

# ── Dispatcher appelé depuis WebSocket ────────────────────────────────────
def run_report(report_type: str, fmt: str, filter_status: str = "all") -> str:
    """Génère un rapport et retourne le chemin du fichier créé"""
    if report_type == "packets":
        return generate_packets_csv(filter_status) if fmt == "csv" else generate_packets_json(filter_status)
    elif report_type == "threats":
        return generate_threats_csv() if fmt == "csv" else generate_threats_json()
    elif report_type == "blocked_ips":
        return generate_blocked_ips_csv() if fmt == "csv" else generate_blocked_ips_json()
    elif report_type == "full":
        return generate_full_report_txt() if fmt == "txt" else generate_full_report_json()
    return ""

# ─── Snapshot périodique ──────────────────────────────────────────────────
def snapshot_traffic():
    """Appelé chaque seconde pour enregistrer un point dans l'historique"""
    with STATE.lock:
        snap = {
            "ts":      time.time(),
            "in_bps":  STATE.bytes_in,
            "out_bps": STATE.bytes_out,
            "blocked": STATE.packets_blocked,
            "pps":     STATE.packets_total,
        }
        STATE.traffic_history.append(snap)
        STATE.bytes_in    = 0
        STATE.bytes_out   = 0

# ─── API WebSocket ────────────────────────────────────────────────────────
CLIENTS: set = set()

def build_state_message() -> dict:
    with STATE.lock:
        conns_count = sum(len(v) for v in STATE.active_conns.values())
        total = max(STATE.packets_total, 1)
        proto_total = sum(STATE.proto_stats.values()) or 1
        rules_out = [
            {
                "key":     k,
                "label":   v["label"],
                "enabled": v["enabled"],
                "hits":    v["hits"],
            }
            for k, v in RULES.items()
        ]
        return {
            "type":           "state",
            "ts":             time.time(),
            "packets_total":  STATE.packets_total,
            "packets_blocked":STATE.packets_blocked,
            "blocked_rate":   round(STATE.packets_blocked * 100 / total, 1),
            "active_conns":   conns_count,
            "threats_count":  len(STATE.threats),
            "recent_packets": list(STATE.recent_packets)[:30],
            "threats":        list(STATE.threats)[:10],
            "traffic_history":list(STATE.traffic_history),
            "proto_stats": [
                {"name": k, "count": v, "pct": round(v * 100 / proto_total, 1)}
                for k, v in sorted(STATE.proto_stats.items(), key=lambda x: -x[1])
            ],
            "blocked_ips":           list(BLOCKED_IPS)[:50],
            "rules":                 rules_out,
            "detection_params":      DETECTION_PARAMS,
            "geo_blocked_countries": list(GEO_BLOCKED_COUNTRIES),
            "geo_country_names":     GEO_COUNTRY_NAMES,
        }

async def ws_handler(websocket):
    global CLIENTS
    CLIENTS.add(websocket)
    log.info(f"[WS] Client connecté: {websocket.remote_address}")
    try:
        # Envoyer état initial
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
    """Commandes envoyées depuis le tableau de bord"""
    cmd = msg.get("cmd")

    if cmd == "get_state":
        await ws.send(json.dumps(build_state_message()))

    elif cmd == "toggle_rule":
        key = msg.get("rule")
        if key in RULES:
            RULES[key]["enabled"] = not RULES[key]["enabled"]
            state_str = "activée" if RULES[key]["enabled"] else "désactivée"
            log.info(f"[RULE] {RULES[key]['label']} {state_str}")
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

    elif cmd == "update_param":
        key = msg.get("key")
        val = msg.get("value")
        if key in DETECTION_PARAMS:
            p = DETECTION_PARAMS[key]
            val = max(p["min"], min(p["max"], int(val)))
            DETECTION_PARAMS[key]["value"] = val
            # Sync to CFG
            if hasattr(CFG, key):
                setattr(CFG, key, val)
            log.info(f"[PARAM] {key} = {val}")
            await ws.send(json.dumps({"type": "param_updated", "key": key, "value": val}))

    elif cmd == "set_geo_countries":
        global GEO_BLOCKED_COUNTRIES
        countries = msg.get("countries", [])
        GEO_BLOCKED_COUNTRIES = set(countries)
        log.info(f"[GEO] Pays bloqués: {GEO_BLOCKED_COUNTRIES}")
        await ws.send(json.dumps({"type": "geo_updated", "countries": list(GEO_BLOCKED_COUNTRIES)}))

    elif cmd == "generate_report":
        rtype  = msg.get("report_type", "full")   # packets / threats / blocked_ips / full
        fmt    = msg.get("format", "txt")          # csv / json / txt
        filt   = msg.get("filter", "all")          # all / block / warn
        try:
            filepath = run_report(rtype, fmt, filt)
            await ws.send(json.dumps({
                "type":     "report_ready",
                "path":     filepath,
                "report_type": rtype,
                "format":   fmt,
            }))
        except Exception as e:
            await ws.send(json.dumps({"type": "report_error", "error": str(e)}))

async def broadcast_state():
    """Envoie l'état à tous les clients connectés chaque seconde"""
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

# ─── Capture de paquets ────────────────────────────────────────────────────
def auto_select_interface() -> str:
    if not HAS_SCAPY:
        return "eth0"
    ifaces = get_if_list()
    # Préférer Wi-Fi ou ethernet
    for pref in ["Wi-Fi", "wlan0", "wlan1", "eth0", "en0", "Ethernet"]:
        for iface in ifaces:
            if pref.lower() in iface.lower():
                return iface
    return ifaces[0] if ifaces else "eth0"

def start_capture(interface: str):
    if not HAS_SCAPY:
        log.error("scapy non disponible — capture impossible.")
        log.info("Mode DEMO: génération de trafic simulé activée")
        _run_demo_mode()
        return

    log.info(f"[CAPTURE] Démarrage sur interface: {interface}")
    try:
        sniff(
            iface=interface,
            prn=analyze_packet,
            store=False,
            filter="ip or arp",  # BPF filter — moins de charge CPU
        )
    except PermissionError:
        log.error("ERREUR: Permissions insuffisantes. Lance avec sudo (Linux) ou en tant qu'Administrateur (Windows).")
        sys.exit(1)
    except Exception as e:
        log.error(f"Erreur capture: {e}")
        log.info("Mode DEMO activé suite à l'erreur")
        _run_demo_mode()

def _run_demo_mode():
    """Génère du trafic simulé si scapy n'est pas dispo (démo/test)"""
    import random
    log.info("[DEMO] Mode démonstration — trafic simulé")
    IPS = ["192.168.1.10","10.0.0.5","45.33.32.156","185.220.101.34",
           "91.108.4.1","77.88.55.66","203.0.113.1","198.51.100.5"]
    PROTOS = ["TCP","UDP","DNS","HTTPS","HTTP","SSH","RDP"]
    while True:
        time.sleep(0.08)
        with STATE.lock:
            src = random.choice(IPS)
            dst = "192.168.1.1"
            proto = random.choice(PROTOS)
            port  = {"TCP":80,"UDP":53,"DNS":53,"HTTPS":443,"HTTP":80,"SSH":22,"RDP":3389}[proto]
            is_bad = not is_private(src) and random.random() < 0.2
            status = "block" if is_bad else "allow"
            reason = random.choice(["Scan de ports","Brute Force SSH","IP blacklistée","","",""]) if is_bad else ""
            STATE.packets_total += 1
            STATE.proto_stats[proto] += 1
            if is_bad: STATE.packets_blocked += 1
            else:      STATE.packets_allowed += 1
            STATE.bytes_in += random.randint(40, 1500)
            entry = {
                "t":     datetime.now().strftime("%H:%M:%S"),
                "src":   src,"dst": dst,
                "sport": random.randint(1024,65535),
                "dport": port,"proto": proto,
                "size":  f"{random.randint(40,1500)}B",
                "status":status,"reason":reason,"flags":"S" if proto=="TCP" else "",
            }
            STATE.recent_packets.appendleft(entry)
            if is_bad and random.random() < 0.3:
                STATE.threats.appendleft({
                    "id":          int(time.time()*1000),
                    "timestamp":   datetime.now().isoformat(),
                    "src_ip":      src,
                    "type":        reason or "Activité suspecte",
                    "description": f"Détecté depuis {src}",
                    "severity":    random.choice(["high","med","low"]),
                    "blocked":     True,
                })

# ─── Point d'entrée ───────────────────────────────────────────────────────
async def main_async(interface: str):
    capture_thread = threading.Thread(
        target=start_capture, args=(interface,), daemon=True
    )
    capture_thread.start()
    log.info(f"[WS] Serveur WebSocket sur ws://localhost:{CFG.ws_port}")

    if HAS_WS:
        async with websockets.serve(ws_handler, "localhost", CFG.ws_port):
            await broadcast_state()
    else:
        # Sans WebSocket, juste capturer et logger
        while True:
            await asyncio.sleep(1)
            snapshot_traffic()

def main():
    parser = argparse.ArgumentParser(description="NetGuard Pro — Surveillance réseau")
    parser.add_argument("--interface", default="auto",   help="Interface réseau (défaut: auto)")
    parser.add_argument("--port",      type=int, default=8765, help="Port WebSocket (défaut: 8765)")
    parser.add_argument("--no-block",  action="store_true",    help="Mode surveillance uniquement (pas de blocage)")
    parser.add_argument("--demo",      action="store_true",    help="Mode démonstration (sans capture réelle)")
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

    print("""
╔══════════════════════════════════════════════╗
║         NetGuard Pro — Démarrage             ║
╠══════════════════════════════════════════════╣
║  Surveillance réseau + blocage intelligent   ║
║  Dashboard: netguard_dashboard.html          ║
╚══════════════════════════════════════════════╝
""")

    if not CFG.can_block:
        log.info("[MODE] Surveillance uniquement — blocage désactivé")
    else:
        log.info("[MODE] Protection active — blocage OS activé")

    try:
        asyncio.run(main_async(interface))
    except KeyboardInterrupt:
        log.info("Arrêt de NetGuard Pro.")

if __name__ == "__main__":
    main()
