"""
NetGuard Pro - Moteur de surveillance réseau
Capture, analyse et bloque les paquets en temps réel
Auteur: NetGuard Pro
Version: 2.3.0
Usage: python netguard.py [--interface eth0] [--port 8765] [--no-block] [--api] [--kiosk]
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
import subprocess
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta
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
_geo_city_cache: dict = {}  # ip -> {city, country, country_name}

def get_geo_info(ip: str) -> dict:
    """Retourne {country, country_name, city} pour une IP — cache local d'abord, API ensuite"""
    if ip in _geo_city_cache:
        return _geo_city_cache[ip]
    country = get_country(ip)
    result = {
        "country": country or "?",
        "country_name": GEO_COUNTRY_NAMES.get(country, country or "Inconnu"),
        "city": "",
    }
    # Essayer l'API ipapi.co en arrière-plan (non bloquant)
    _geo_city_cache[ip] = result
    return result

def _fetch_city_async(ip: str):
    """Récupère la ville et coordonnées en arrière-plan"""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/2.3"})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        _geo_city_cache[ip] = {
            "country":   data.get("country_code", ""),
            "country_name": data.get("country_name", ""),
            "city":      data.get("city", ""),
            "latitude":  data.get("latitude"),
            "longitude": data.get("longitude"),
            "org":       data.get("org", ""),
            "asn":       data.get("asn", ""),
        }
        _update_ip_intel(ip, data)
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════
# v2.2.0 — BLACKLIST COMMUNAUTAIRE
# ═══════════════════════════════════════════════════════════════════════════

COMMUNITY_BLACKLIST: set = set()
_BLACKLIST_LAST_UPDATE: float = 0
BLACKLIST_UPDATE_INTERVAL: int = 3600 * 6

def update_community_blacklist():
    global COMMUNITY_BLACKLIST, _BLACKLIST_LAST_UPDATE
    if time.time() - _BLACKLIST_LAST_UPDATE < BLACKLIST_UPDATE_INTERVAL:
        return
    new_ips = set()
    sources = [
        ("Spamhaus DROP",  "https://www.spamhaus.org/drop/drop.txt"),
        ("Spamhaus EDROP", "https://www.spamhaus.org/drop/edrop.txt"),
        ("Blocklist.de",   "https://lists.blocklist.de/lists/all.txt"),
    ]
    for name, url in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuardPro/2.3"})
            with urllib.request.urlopen(req, timeout=10) as r:
                for line in r.read().decode(errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith(";") or line.startswith("#"):
                        continue
                    ip = line.split(";")[0].split()[0].strip()
                    try:
                        ipaddress.ip_address(ip)
                        new_ips.add(ip)
                    except ValueError:
                        try:
                            net = ipaddress.ip_network(ip, strict=False)
                            if net.prefixlen >= 20:
                                new_ips.update(str(h) for h in list(net.hosts())[:50])
                        except ValueError:
                            pass
            log.info(f"[BLACKLIST] {name}: OK")
        except Exception as e:
            log.warning(f"[BLACKLIST] {name}: {e}")
    if new_ips:
        COMMUNITY_BLACKLIST = new_ips
        _BLACKLIST_LAST_UPDATE = time.time()
        log.info(f"[BLACKLIST] {len(COMMUNITY_BLACKLIST)} IPs chargées")

def is_community_blacklisted(ip: str) -> bool:
    return ip in COMMUNITY_BLACKLIST

# ═══════════════════════════════════════════════════════════════════════════
# v2.2.0 — RATE LIMITING DYNAMIQUE
# ═══════════════════════════════════════════════════════════════════════════

_rate_limit_tracker: dict = {}
RATE_LIMIT_LEVELS = [
    {"threshold": 10,  "window": 5,  "action": "warn",    "label": "Suspect"},
    {"threshold": 30,  "window": 10, "action": "throttle","label": "Ralenti"},
    {"threshold": 60,  "window": 15, "action": "block",   "label": "Bloqué"},
]

def rate_limit_check(ip: str) -> Optional[dict]:
    if is_private(ip):
        return None
    now = time.time()
    if ip not in _rate_limit_tracker:
        _rate_limit_tracker[ip] = {"count": 0, "window_start": now, "level": 0}
    tracker = _rate_limit_tracker[ip]
    elapsed = now - tracker["window_start"]
    if elapsed > 60:
        tracker["count"] = 0
        tracker["window_start"] = now
        tracker["level"] = 0
    tracker["count"] += 1
    for i, level in enumerate(RATE_LIMIT_LEVELS):
        if tracker["count"] >= level["threshold"] and elapsed <= level["window"]:
            tracker["level"] = i
            return level
    return None

def get_rate_limit_stats() -> list:
    now = time.time()
    stats = []
    for ip, data in _rate_limit_tracker.items():
        if data["count"] >= RATE_LIMIT_LEVELS[0]["threshold"]:
            elapsed = max(now - data["window_start"], 1)
            stats.append({
                "ip":    ip,
                "count": data["count"],
                "rate":  round(data["count"] / elapsed, 1),
                "level": data.get("level", 0),
                "label": RATE_LIMIT_LEVELS[min(data.get("level",0), len(RATE_LIMIT_LEVELS)-1)]["label"],
            })
    return sorted(stats, key=lambda x: -x["count"])[:20]

# ═══════════════════════════════════════════════════════════════════════════
# v2.2.0 — FINGERPRINTING OS
# ═══════════════════════════════════════════════════════════════════════════

_os_fingerprints: dict = {}

OS_TTL_MAP = [
    (64,  "Linux / Android", "🐧"),
    (128, "Windows",         "🪟"),
    (255, "Cisco / Réseau",  "🔧"),
    (254, "Solaris / macOS", "🍎"),
    (60,  "macOS",           "🍎"),
]
OS_WINDOW_MAP = {
    8192:  ("Windows 7/10/11","🪟"),
    65535: ("BSD / macOS",    "🍎"),
    5840:  ("Linux",          "🐧"),
    5720:  ("Linux",          "🐧"),
    14600: ("Linux",          "🐧"),
    29200: ("Linux 4.x",      "🐧"),
}

def fingerprint_os(pkt) -> Optional[dict]:
    if not HAS_SCAPY or not pkt.haslayer(IP):
        return None
    try:
        ip_layer = pkt[IP]
        ttl, src_ip = ip_layer.ttl, ip_layer.src
        os_guess, os_icon, confidence = "Inconnu", "❓", 0
        for ref_ttl, name, icon in OS_TTL_MAP:
            if abs(ttl - ref_ttl) <= 5:
                os_guess, os_icon, confidence = name, icon, 60
                break
        if pkt.haslayer(TCP) and pkt[TCP].window in OS_WINDOW_MAP:
            os_guess, os_icon = OS_WINDOW_MAP[pkt[TCP].window]
            confidence = 80
        result = {"os": os_guess, "icon": os_icon, "ttl": ttl, "confidence": confidence}
        if src_ip not in _os_fingerprints:
            _os_fingerprints[src_ip] = result
        return result
    except Exception:
        return None
_KNOWN_VPN_ORGS = [
    "nordvpn","expressvpn","surfshark","mullvad","protonvpn","ipvanish",
    "cyberghost","privatevpn","strongvpn","hidemyass","torguard","airvpn",
    "windscribe","tunnelbear","ivpn","ovpn","perfect privacy","hide.me",
    "tor exit","torproject","digitalocean","vultr","linode","hetzner",
    "contabo","hostinger vpn","datacenter","hosting","vps","cloud"
]
_KNOWN_TOR_EXITS: set = set()  # populated lazily
_ABUSEIPDB_CACHE: dict = {}    # ip -> {score, reports}
ABUSEIPDB_API_KEY: str = ""    # Set via config if user has key

def _update_ip_intel(ip: str, geo_data: dict):
    """Met à jour le profil intel d'une IP"""
    org = (geo_data.get("org") or "").lower()
    is_vpn = any(kw in org for kw in _KNOWN_VPN_ORGS)
    is_tor  = ip in _KNOWN_TOR_EXITS

    intel = STATE.ip_intel.get(ip, {})
    intel.update({
        "org":     geo_data.get("org", ""),
        "asn":     geo_data.get("asn", ""),
        "vpn":     is_vpn,
        "tor":     is_tor,
        "country": geo_data.get("country_code", ""),
        "city":    geo_data.get("city", ""),
    })
    STATE.ip_intel[ip] = intel
    _compute_risk_score(ip)

def _compute_risk_score(ip: str) -> int:
    """Calcule un score de risque 0-100 pour une IP"""
    score = 0
    intel = STATE.ip_intel.get(ip, {})
    hits  = STATE.ip_hit_counter.get(ip, 0)
    is_blocked = ip in BLOCKED_IPS

    # Hits répétés
    if hits >= 50:  score += 30
    elif hits >= 20: score += 20
    elif hits >= 5:  score += 10

    # VPN/Proxy
    if intel.get("vpn"): score += 20
    if intel.get("tor"): score += 35

    # Bloqué
    if is_blocked: score += 25

    # AbuseIPDB
    abuse = _ABUSEIPDB_CACHE.get(ip, {})
    if abuse.get("score", 0) > 50: score += 20
    elif abuse.get("score", 0) > 20: score += 10

    # Pays à risque élevé
    HIGH_RISK = {"KP", "IR", "RU", "NG"}
    MED_RISK  = {"CN", "BR", "IN", "UA"}
    country = intel.get("country", get_country(ip) or "")
    if country in HIGH_RISK: score += 15
    elif country in MED_RISK: score += 8

    # Menaces détectées
    threat_count = sum(1 for t in STATE.threats if t.get("src_ip") == ip)
    score += min(threat_count * 5, 25)

    score = min(score, 100)
    STATE.ip_risk_scores[ip] = score
    return score

def _fetch_abuseipdb(ip: str):
    """Vérifie l'IP sur AbuseIPDB (si clé API configurée)"""
    if not ABUSEIPDB_API_KEY or ip in _ABUSEIPDB_CACHE:
        return
    try:
        import urllib.request
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": ABUSEIPDB_API_KEY, "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        d = data.get("data", {})
        _ABUSEIPDB_CACHE[ip] = {
            "score":   d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "domain":  d.get("domain", ""),
            "isp":     d.get("isp", ""),
        }
        _compute_risk_score(ip)
    except Exception:
        pass

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
        # v1.9.0
        self.ip_risk_scores        = {}           # ip -> score 0-100
        self.ip_intel              = {}           # ip -> {vpn, tor, abusive, org, ...}
        self.attack_by_country     = defaultdict(lambda: defaultdict(int))  # country -> type -> count
        self.timeline_events       = deque(maxlen=300)  # {ts, type, ip, country, severity}

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
    country = get_country(src_ip) or ""
    now = datetime.now()
    threat = {
        "id":          int(time.time() * 1000),
        "timestamp":   now.isoformat(),
        "src_ip":      src_ip,
        "type":        threat_type,
        "description": description,
        "severity":    severity,
        "blocked":     src_ip in BLOCKED_IPS,
        "country":     country,
    }
    STATE.threats.appendleft(threat)
    if rule_key and rule_key in RULES:
        RULES[rule_key]["hits"] += 1

    # Track attack type by country
    if country:
        t = threat_type.lower()
        if "scan" in t or "port" in t:               cat = "Scan"
        elif "brute" in t or "ssh" in t:             cat = "Brute Force"
        elif "flood" in t or "dos" in t:             cat = "DDoS"
        elif "dns" in t:                             cat = "DNS"
        elif "dpi" in t or "sql" in t or "xss" in t: cat = "Web"
        elif "ids" in t or "suricata" in t:          cat = "IDS"
        elif "malware" in t or "c2" in t:            cat = "Malware"
        else:                                        cat = "Autre"
        STATE.attack_by_country[country][cat] += 1

    # Timeline
    STATE.timeline_events.appendleft({
        "ts":       now.strftime("%H:%M:%S"),
        "date":     now.strftime("%Y-%m-%d"),
        "type":     threat_type,
        "ip":       src_ip,
        "country":  country,
        "severity": severity,
    })

    # Update risk score
    _compute_risk_score(src_ip)

    # Envoyer alerte si sévérité suffisante
    if severity in ("critical", "high"):
        threading.Thread(target=send_alert, args=(threat,), daemon=True).start()

    # Sauvegarder dans l'historique persistant
    threading.Thread(target=history_append, args=(threat,), daemon=True).start()

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

        # ── Community Blacklist ─────────────────────────────────────────
        if decision == "allow" and not is_private(src_ip) and is_community_blacklisted(src_ip):
            decision = "block"
            reason   = "Blacklist communautaire (Spamhaus/Blocklist.de)"
            add_threat(src_ip, "Blacklist communautaire", f"IP dans la blacklist Spamhaus/Blocklist.de", "high")

        # ── Rate Limiting dynamique ─────────────────────────────────────
        if decision == "allow" and not is_private(src_ip):
            rl = rate_limit_check(src_ip)
            if rl:
                if rl["action"] == "block":
                    decision = "block"
                    reason   = f"Rate limit: {rl['label']} ({rl['threshold']} req/{rl['window']}s)"
                    add_threat(src_ip, "Rate Limit", f"{rl['label']}: {rl['threshold']}+ paquets/{rl['window']}s", "med")
                elif rl["action"] == "warn" and decision == "allow":
                    decision = "warn"
                    reason   = f"Rate limit: {rl['label']}"

        # ── Fingerprinting OS ───────────────────────────────────────────
        if HAS_SCAPY and src_ip not in _os_fingerprints:
            fingerprint_os(pkt)

        # ── DNS Blackhole ───────────────────────────────────────────────
        if RULES.get("detect_malicious_dns", {}).get("enabled", True) and pkt.haslayer("DNS"):
            try:
                from scapy.layers.dns import DNS, DNSQR
                if pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    queried = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                    if dns_blackhole_check(queried):
                        decision = "block"
                        reason   = f"DNS Blackhole: {queried}"
                        add_threat(src_ip, "DNS Blackhole", f"Requête vers domaine bloqué: {queried}", "high")
            except Exception:
                pass

        # ── Géoblocage
        if GEO_BLOCKED_COUNTRIES and not is_private(src_ip):
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
            # Track geo hits for attacker stats
            country = get_country(src_ip)
            if country:
                STATE.geo_hits[country] += 1
                # Fetch city async if not cached yet
                if src_ip not in _geo_city_cache:
                    threading.Thread(target=_fetch_city_async, args=(src_ip,), daemon=True).start()
                # Fetch AbuseIPDB async if key configured
                if ABUSEIPDB_API_KEY and src_ip not in _ABUSEIPDB_CACHE:
                    threading.Thread(target=_fetch_abuseipdb, args=(src_ip,), daemon=True).start()

        # Fetch intel for any new external IP
        if not is_private(src_ip) and src_ip not in STATE.ip_intel:
            threading.Thread(target=_fetch_city_async, args=(src_ip,), daemon=True).start()

        # Update risk score
        _compute_risk_score(src_ip)

        if decision == "block":
            STATE.packets_blocked += 1
        else:
            STATE.packets_allowed += 1
            STATE.active_conns[src_ip].add(dst_port)

        # Get geo info for packet entry
        geo = _geo_city_cache.get(src_ip, {})
        country_code = geo.get("country") or get_country(src_ip) or ""
        city = geo.get("city", "")
        lat  = geo.get("latitude")
        lon  = geo.get("longitude")
        location = f"{city}, {GEO_COUNTRY_NAMES.get(country_code, country_code)}" if city else GEO_COUNTRY_NAMES.get(country_code, country_code)

        STATE.recent_packets.appendleft({
            "t":        datetime.now().strftime("%H:%M:%S"),
            "src":      src_ip, "dst": dst_ip,
            "sport":    src_port, "dport": dst_port,
            "proto":    proto, "size": f"{pkt_len}B",
            "status":   decision, "reason": reason, "flags": flags,
            "country":  country_code,
            "city":     city,
            "location": location,
            "lat":      lat,
            "lon":      lon,
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
            "geo_hits": [
                {"country": k, "name": GEO_COUNTRY_NAMES.get(k, k), "hits": v}
                for k, v in sorted(STATE.geo_hits.items(), key=lambda x: -x[1])
            ],
            # v1.9.0
            "ip_risk_scores": dict(list(sorted(STATE.ip_risk_scores.items(), key=lambda x: -x[1]))[:20]),
            "ip_intel": {ip: STATE.ip_intel[ip] for ip in list(STATE.ip_intel.keys())[:50]},
            "attack_by_country": {
                country: dict(types)
                for country, types in sorted(STATE.attack_by_country.items(),
                    key=lambda x: -sum(x[1].values()))[:15]
            },
            "timeline": list(STATE.timeline_events)[:100],
            # v2.0.0
            "honeypot_enabled": HONEYPOT_ENABLED,
            "honeypot_hits":    HONEYPOT_HITS[-20:],
            "dns_blackhole_count": len(DNS_BLACKHOLE),
            "dns_blackhole_hits":  sum(DNS_BLACKHOLE_HITS.values()),
            "lan_devices":      LAN_DEVICES,
            # v2.2.0
            "os_fingerprints":  dict(list(_os_fingerprints.items())[-30:]),
            "rate_limit_stats": get_rate_limit_stats(),
            "blacklist_size":   len(COMMUNITY_BLACKLIST),
            "blacklist_updated": _BLACKLIST_LAST_UPDATE > 0,
        }

# ═══════════════════════════════════════════════════════════════════════════
# v2.0.0 — DÉFENSE ACTIVE
# ═══════════════════════════════════════════════════════════════════════════

# ─── DNS Blackhole ─────────────────────────────────────────────────────────
DNS_BLACKHOLE: set = set()  # domaines bloqués
DNS_BLACKHOLE_HITS: dict = {}  # domaine -> hits

DEFAULT_BLACKHOLE_DOMAINS = [
    # Malware C2
    "emotet.com","trickbot.com","cobaltrike.com","metasploit.com",
    # Trackers publicitaires connus
    "doubleclick.net","googlesyndication.com","adnxs.com","scorecardresearch.com",
    # Phishing connus
    "phishing.example.com",
    # Cryptomining
    "coinhive.com","coin-hive.com","crypto-loot.com","minero.cc",
    # Telemetry Windows (optionnel)
    "telemetry.microsoft.com","vortex.data.microsoft.com",
]

def dns_blackhole_check(domain: str) -> bool:
    """Vérifie si un domaine est dans la blacklist DNS"""
    if not domain:
        return False
    domain = domain.lower().rstrip(".")
    # Check exact + parent domains
    for blocked in DNS_BLACKHOLE:
        if domain == blocked or domain.endswith("." + blocked):
            DNS_BLACKHOLE_HITS[blocked] = DNS_BLACKHOLE_HITS.get(blocked, 0) + 1
            return True
    return False

def dns_blackhole_add(domains: list):
    """Ajoute des domaines à la blacklist"""
    for d in domains:
        d = d.lower().strip().rstrip(".")
        if d:
            DNS_BLACKHOLE.add(d)
    log.info(f"[DNS-BH] {len(DNS_BLACKHOLE)} domaines dans la blacklist")

def dns_blackhole_remove(domain: str):
    DNS_BLACKHOLE.discard(domain.lower().strip())

# Init avec les domaines par défaut
dns_blackhole_add(DEFAULT_BLACKHOLE_DOMAINS)

# ─── Scan LAN ──────────────────────────────────────────────────────────────
LAN_DEVICES: list = []
LAN_SCAN_RUNNING: bool = False

def _get_local_subnet() -> str:
    """Détecte automatiquement le sous-réseau local"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"

def scan_lan() -> list:
    """Scanne le réseau local et retourne les appareils trouvés"""
    global LAN_SCAN_RUNNING, LAN_DEVICES
    if LAN_SCAN_RUNNING:
        return LAN_DEVICES
    LAN_SCAN_RUNNING = True
    devices = []
    try:
        import socket
        import struct
        import subprocess

        subnet = _get_local_subnet()
        log.info(f"[LAN] Scan du sous-réseau: {subnet}")

        # Méthode 1 : ARP scan via scapy
        if HAS_SCAPY:
            try:
                from scapy.layers.l2 import ARP, Ether
                from scapy.sendrecv import srp
                arp = ARP(pdst=subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=3, verbose=False)[0]
                for sent, received in result:
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                    except Exception:
                        pass
                    devices.append({
                        "ip":       received.psrc,
                        "mac":      received.hwsrc,
                        "hostname": hostname,
                        "vendor":   _mac_vendor(received.hwsrc),
                        "status":   "up",
                        "open_ports": [],
                    })
            except Exception as e:
                log.warning(f"[LAN] ARP scan failed: {e}")

        # Méthode 2 : ping sweep si scapy ne fonctionne pas
        if not devices:
            base = subnet.rsplit(".", 1)[0]
            import concurrent.futures
            def ping_host(i):
                ip = f"{base}.{i}"
                try:
                    result = subprocess.run(
                        ["ping", "-n", "1", "-w", "200", ip] if os.name == "nt"
                        else ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True, timeout=2
                    )
                    if result.returncode == 0:
                        hostname = ""
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            pass
                        return {"ip": ip, "mac": "—", "hostname": hostname, "vendor": "—", "status": "up", "open_ports": []}
                except Exception:
                    pass
                return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(ping_host, range(1, 255)))
            devices = [r for r in results if r]

        LAN_DEVICES = devices
        log.info(f"[LAN] {len(devices)} appareils trouvés")

    except Exception as e:
        log.error(f"[LAN] Erreur scan: {e}")
    finally:
        LAN_SCAN_RUNNING = False

    return devices

def _mac_vendor(mac: str) -> str:
    """Identifie le fabricant via les 3 premiers octets du MAC"""
    vendors = {
        "00:50:56": "VMware", "00:0c:29": "VMware", "00:15:5d": "Hyper-V",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
        "00:1a:11": "Google", "f4:f5:d8": "Google",
        "ac:bc:32": "Apple", "3c:22:fb": "Apple", "a4:c3:f0": "Apple",
        "00:50:f2": "Microsoft", "28:18:78": "Microsoft",
        "00:1b:21": "Intel", "8c:ec:4b": "Intel",
        "14:59:c0": "Cisco", "00:1e:bd": "Cisco",
    }
    prefix = mac[:8].lower()
    for k, v in vendors.items():
        if mac.lower().startswith(k.lower()):
            return v
    return "Inconnu"

# ─── Honeypot ──────────────────────────────────────────────────────────────
HONEYPOT_ENABLED: bool = False
HONEYPOT_HITS: list = []
HONEYPOT_SERVERS: list = []

class HoneypotServer:
    """Faux service qui logue toutes les connexions"""
    def __init__(self, port: int, service_name: str, banner: str):
        self.port = port
        self.service_name = service_name
        self.banner = banner.encode() + b"\r\n"
        self.server = None
        self.running = False

    async def handle_client(self, reader, writer):
        ip = writer.get_extra_info('peername')[0]
        log.warning(f"[HONEYPOT] {self.service_name}:{self.port} — connexion de {ip}")

        # Log l'intrusion
        hit = {
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "ip":      ip,
            "port":    self.port,
            "service": self.service_name,
            "country": get_country(ip) or "?",
        }
        HONEYPOT_HITS.append(hit)
        if len(HONEYPOT_HITS) > 200:
            HONEYPOT_HITS.pop(0)

        # Ajouter comme menace
        add_threat(ip, f"Honeypot {self.service_name}", f"Connexion sur faux service port {self.port}", "high")
        auto_block_check(ip)

        try:
            writer.write(self.banner)
            await writer.drain()
            # Lire un peu de données (credentials tentés)
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=5)
                if data:
                    hit["data"] = data.decode(errors="replace")[:100]
                    log.warning(f"[HONEYPOT] Données reçues de {ip}: {hit['data'][:50]}")
            except asyncio.TimeoutError:
                pass
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self):
        try:
            self.server = await asyncio.start_server(self.handle_client, "0.0.0.0", self.port)
            self.running = True
            log.info(f"[HONEYPOT] {self.service_name} sur port {self.port}")
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            log.error(f"[HONEYPOT] Erreur port {self.port}: {e}")

HONEYPOT_CONFIGS = [
    (22,   "SSH",   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
    (23,   "Telnet","Welcome to Ubuntu 22.04 LTS"),
    (21,   "FTP",   "220 FTP server ready"),
    (3389, "RDP",   "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00"),
    (8080, "HTTP",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"),
]

async def start_honeypots():
    global HONEYPOT_SERVERS
    HONEYPOT_SERVERS = []
    for port, name, banner in HONEYPOT_CONFIGS:
        hp = HoneypotServer(port, name, banner)
        HONEYPOT_SERVERS.append(hp)
        asyncio.create_task(hp.start())
    log.info(f"[HONEYPOT] {len(HONEYPOT_SERVERS)} services honeypot démarrés")
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
            audit_log(msg.get("user","dashboard"), "BLOCK_IP", ip, reason)
            await ws.send(json.dumps({"type": "ip_blocked", "ip": ip}))
    elif cmd == "unblock_ip":
        ip = msg.get("ip", "")
        if ip:
            unblock_ip_os(ip)
            audit_log(msg.get("user","dashboard"), "UNBLOCK_IP", ip)
            await ws.send(json.dumps({"type": "ip_unblocked", "ip": ip}))
    elif cmd == "get_blocked_ips":
        await ws.send(json.dumps({"type": "blocked_ips", "ips": list(BLOCKED_IPS)}))
    elif cmd == "clear_threats":
        audit_log(msg.get("user","dashboard"), "CLEAR_THREATS", "", "Effacement manuel des menaces")
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

    elif cmd == "set_geo_countries":
        global GEO_BLOCKED_COUNTRIES
        countries = msg.get("countries", [])
        GEO_BLOCKED_COUNTRIES = set(countries)
        log.info(f"[GEO] Pays bloqués: {GEO_BLOCKED_COUNTRIES}")
        await ws.send(json.dumps({"type": "geo_updated", "countries": list(GEO_BLOCKED_COUNTRIES)}))
        save_settings()

    # ── DNS Blackhole ──────────────────────────────────────────────────────
    elif cmd == "dns_blackhole_add":
        domains = msg.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.replace(",","\n").splitlines() if d.strip()]
        dns_blackhole_add(domains)
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":list(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    elif cmd == "dns_blackhole_remove":
        dns_blackhole_remove(msg.get("domain",""))
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":list(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    elif cmd == "dns_blackhole_get":
        await ws.send(json.dumps({"type":"dns_blackhole_updated","domains":sorted(DNS_BLACKHOLE),"hits":DNS_BLACKHOLE_HITS}))

    # ── Scan LAN ───────────────────────────────────────────────────────────
    elif cmd == "scan_lan":
        await ws.send(json.dumps({"type":"lan_scan_started","subnet":_get_local_subnet()}))
        def _do_scan():
            devices = scan_lan()
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type":"lan_scan_result","devices":devices,"count":len(devices)})),
                asyncio.get_event_loop()
            )
        threading.Thread(target=_do_scan, daemon=True).start()

    # ── Honeypot ───────────────────────────────────────────────────────────
    elif cmd == "toggle_honeypot":
        global HONEYPOT_ENABLED
        HONEYPOT_ENABLED = not HONEYPOT_ENABLED
        if HONEYPOT_ENABLED and not HONEYPOT_SERVERS:
            asyncio.create_task(start_honeypots())
        await ws.send(json.dumps({"type":"honeypot_toggled","enabled":HONEYPOT_ENABLED,"ports":[p for p,_,_ in HONEYPOT_CONFIGS]}))

    elif cmd == "get_honeypot_hits":
        await ws.send(json.dumps({"type":"honeypot_hits","hits":HONEYPOT_HITS[-50:],"enabled":HONEYPOT_ENABLED}))

    # ── Alertes email + toast ──────────────────────────────────────────────
    elif cmd == "get_alert_config":
        await ws.send(json.dumps({
            "type": "alert_config",
            "email_enabled":  ALERT_CFG.email_enabled,
            "email_from":     ALERT_CFG.email_from,
            "email_to":       ALERT_CFG.email_to,
            "email_smtp":     ALERT_CFG.email_smtp,
            "email_port":     ALERT_CFG.email_port,
            "email_min_sev":  ALERT_CFG.email_min_sev,
            "toast_enabled":  ALERT_CFG.toast_enabled,
            "toast_min_sev":  ALERT_CFG.toast_min_sev,
            "alert_cooldown": ALERT_CFG.alert_cooldown,
        }))

    elif cmd == "save_alert_config":
        ALERT_CFG.email_enabled  = msg.get("email_enabled", False)
        ALERT_CFG.email_from     = msg.get("email_from", "")
        ALERT_CFG.email_to       = msg.get("email_to", "")
        ALERT_CFG.email_smtp     = msg.get("email_smtp", "smtp.gmail.com")
        ALERT_CFG.email_port     = int(msg.get("email_port", 587))
        ALERT_CFG.email_password = msg.get("email_password", "")
        ALERT_CFG.email_min_sev  = msg.get("email_min_sev", "high")
        ALERT_CFG.toast_enabled  = msg.get("toast_enabled", True)
        ALERT_CFG.toast_min_sev  = msg.get("toast_min_sev", "high")
        ALERT_CFG.alert_cooldown = int(msg.get("alert_cooldown", 60))
        save_settings()
        await ws.send(json.dumps({"type":"alert_config_saved","ok":True}))
        log.info(f"[ALERTS] Config sauvegardée — email: {ALERT_CFG.email_enabled}, toast: {ALERT_CFG.toast_enabled}")

    elif cmd == "test_alert":
        test_threat = {
            "src_ip":      "185.220.101.5",
            "severity":    "high",
            "type":        "Test NetGuard Pro",
            "description": "Ceci est un test d'alerte — tout fonctionne correctement !",
            "country":     "RU",
            "timestamp":   datetime.now().isoformat(),
        }
        _alert_last_sent.clear()  # reset cooldown pour le test
        send_alert(test_threat)
        await ws.send(json.dumps({"type":"alert_test_sent","ok":True}))

    # ── Historique ─────────────────────────────────────────────────────────
    elif cmd == "get_history":
        period  = msg.get("period", "week")
        data    = history_get(period)
        await ws.send(json.dumps({"type":"history_data","period":period,"data":data[-500:]}))

    elif cmd == "get_history_summary":
        period  = msg.get("period", "week")
        summary = history_summary(period)
        await ws.send(json.dumps({"type":"history_summary","summary":summary}))

    elif cmd == "get_audit":
        limit = msg.get("limit", 200)
        await ws.send(json.dumps({"type":"audit_log","entries":audit_get(limit)}))

    elif cmd == "clear_history":
        period = msg.get("period", "all")
        history_clear(period)
        await ws.send(json.dumps({"type":"history_cleared","period":period,"summary":history_summary("week")}))

    # ── Blacklist communautaire ────────────────────────────────────────────
    elif cmd == "update_blacklist":
        def _do_update():
            global _BLACKLIST_LAST_UPDATE
            _BLACKLIST_LAST_UPDATE = 0  # force refresh
            update_community_blacklist()
            asyncio.run_coroutine_threadsafe(
                ws.send(json.dumps({"type":"blacklist_updated","size":len(COMMUNITY_BLACKLIST)})),
                asyncio.get_event_loop()
            )
        await ws.send(json.dumps({"type":"blacklist_updating"}))
        threading.Thread(target=_do_update, daemon=True).start()

    elif cmd == "get_blacklist_stats":
        await ws.send(json.dumps({
            "type":    "blacklist_stats",
            "size":    len(COMMUNITY_BLACKLIST),
            "updated": _BLACKLIST_LAST_UPDATE,
            "enabled": len(COMMUNITY_BLACKLIST) > 0,
        }))

    # ── Rate limiting ──────────────────────────────────────────────────────
    elif cmd == "get_rate_stats":
        await ws.send(json.dumps({"type":"rate_stats","stats":get_rate_limit_stats()}))

    # ── Fingerprinting ─────────────────────────────────────────────────────
    elif cmd == "get_fingerprints":
        await ws.send(json.dumps({"type":"fingerprints","data":dict(list(_os_fingerprints.items())[-50:])}))

async def broadcast_state():
    global CLIENTS
    save_counter = 0
    log.info("[WS] broadcast_state démarré")
    while True:
        try:
            await asyncio.sleep(1)
            snapshot_traffic()
            save_counter += 1
            if save_counter >= 30:
                save_settings()
                save_counter = 0
                # Backup quotidien
                threading.Thread(target=run_backup, daemon=True).start()
            if CLIENTS:
                msg = json.dumps(build_state_message())
                dead = set()
                for client in list(CLIENTS):
                    try:
                        await client.send(msg)
                    except Exception:
                        dead.add(client)
                CLIENTS = CLIENTS - dead
        except asyncio.CancelledError:
            log.info("[WS] broadcast_state annulé")
            break
        except Exception as e:
            log.error(f"[WS] Erreur broadcast: {e}")
            await asyncio.sleep(1)
            continue

async def ws_handler(websocket):
    global CLIENTS
    # Vérifier le token d'authentification
    token = None
    try:
        path = websocket.request.path if hasattr(websocket, 'request') else ""
        if "?" in path:
            params = dict(p.split("=") for p in path.split("?")[1].split("&") if "=" in p)
            token = params.get("token", "")
    except Exception:
        pass

    # Si auth activée, vérifier le token
    if CFG.__dict__.get("auth_enabled", True) and token:
        session = verify_session(token)
        if not session:
            log.warning(f"[AUTH] Token invalide — connexion refusée: {websocket.remote_address}")
            await websocket.close(1008, "Token invalide")
            return
        log.info(f"[WS] {session['user']} ({session['role']}) connecté")
    
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

    # IPs réalistes par pays avec coordonnées approximatives
    DEMO_IPS = [
        # Russie
        {"ip":"5.8.18.1","country":"RU","city":"Moscou","lat":55.75,"lon":37.6},
        {"ip":"5.44.42.1","country":"RU","city":"Saint-Pétersbourg","lat":59.95,"lon":30.3},
        {"ip":"46.8.19.1","country":"RU","city":"Novosibirsk","lat":55.0,"lon":82.9},
        {"ip":"77.37.200.1","country":"RU","city":"Ekaterinbourg","lat":56.85,"lon":60.6},
        {"ip":"87.226.130.1","country":"RU","city":"Kazan","lat":55.8,"lon":49.1},
        {"ip":"91.108.56.1","country":"RU","city":"Moscou","lat":55.72,"lon":37.65},
        # Chine
        {"ip":"36.99.1.1","country":"CN","city":"Pékin","lat":39.9,"lon":116.4},
        {"ip":"42.200.1.1","country":"CN","city":"Shanghai","lat":31.2,"lon":121.5},
        {"ip":"58.16.1.1","country":"CN","city":"Shenzhen","lat":22.5,"lon":114.1},
        {"ip":"61.135.1.1","country":"CN","city":"Guangzhou","lat":23.1,"lon":113.3},
        {"ip":"101.88.1.1","country":"CN","city":"Chengdu","lat":30.6,"lon":104.1},
        {"ip":"116.31.1.1","country":"CN","city":"Hangzhou","lat":30.25,"lon":120.15},
        # Corée du Nord
        {"ip":"175.45.176.5","country":"KP","city":"Pyongyang","lat":39.0,"lon":125.75},
        # Iran
        {"ip":"5.22.193.1","country":"IR","city":"Téhéran","lat":35.7,"lon":51.4},
        {"ip":"37.98.200.1","country":"IR","city":"Mashhad","lat":36.3,"lon":59.6},
        {"ip":"85.133.1.1","country":"IR","city":"Ispahan","lat":32.65,"lon":51.67},
        # USA
        {"ip":"8.8.100.1","country":"US","city":"New York","lat":40.7,"lon":-74.0},
        {"ip":"13.56.1.1","country":"US","city":"San Francisco","lat":37.75,"lon":-122.4},
        {"ip":"52.200.1.1","country":"US","city":"Seattle","lat":47.6,"lon":-122.3},
        {"ip":"34.100.1.1","country":"US","city":"Chicago","lat":41.85,"lon":-87.6},
        {"ip":"54.239.1.1","country":"US","city":"Dallas","lat":32.8,"lon":-96.8},
        # Allemagne
        {"ip":"46.4.100.1","country":"DE","city":"Berlin","lat":52.5,"lon":13.4},
        {"ip":"81.169.1.1","country":"DE","city":"Francfort","lat":50.1,"lon":8.7},
        {"ip":"85.14.1.1","country":"DE","city":"Munich","lat":48.1,"lon":11.6},
        # France
        {"ip":"37.187.1.1","country":"FR","city":"Paris","lat":48.85,"lon":2.35},
        {"ip":"51.77.1.1","country":"FR","city":"Lyon","lat":45.75,"lon":4.85},
        # Pays-Bas
        {"ip":"31.3.100.1","country":"NL","city":"Amsterdam","lat":52.37,"lon":4.9},
        {"ip":"94.75.1.1","country":"NL","city":"Rotterdam","lat":51.9,"lon":4.45},
        # Nigeria
        {"ip":"41.184.1.1","country":"NG","city":"Lagos","lat":6.45,"lon":3.4},
        {"ip":"197.210.1.1","country":"NG","city":"Abuja","lat":9.07,"lon":7.4},
        # Inde
        {"ip":"103.21.1.1","country":"IN","city":"Mumbai","lat":19.0,"lon":72.85},
        {"ip":"106.64.1.1","country":"IN","city":"Delhi","lat":28.65,"lon":77.2},
        {"ip":"117.192.1.1","country":"IN","city":"Bangalore","lat":12.95,"lon":77.6},
        # Brésil
        {"ip":"177.10.1.1","country":"BR","city":"São Paulo","lat":-23.55,"lon":-46.6},
        {"ip":"189.1.1.1","country":"BR","city":"Rio de Janeiro","lat":-22.9,"lon":-43.2},
        # Royaume-Uni
        {"ip":"51.140.1.1","country":"GB","city":"Londres","lat":51.5,"lon":-0.12},
        {"ip":"81.128.1.1","country":"GB","city":"Manchester","lat":53.5,"lon":-2.25},
        # Japon
        {"ip":"27.80.1.1","country":"JP","city":"Tokyo","lat":35.7,"lon":139.7},
        {"ip":"110.128.1.1","country":"JP","city":"Osaka","lat":34.65,"lon":135.5},
    ]

    PROTOS = ["TCP","UDP","DNS","HTTPS","HTTP","SSH","RDP","ICMP"]
    BAD_REASONS = ["Scan de ports","Brute Force SSH","IP blacklistée","SYN Flood",
                   "DNS Tunneling","HTTP Scanner","Log4Shell","EternalBlue"]

    while True:
        time.sleep(0.06)
        with STATE.lock:
            entry  = random.choice(DEMO_IPS)
            src    = entry["ip"]
            proto  = random.choice(PROTOS)
            port   = {"TCP":80,"UDP":53,"DNS":53,"HTTPS":443,"HTTP":80,"SSH":22,"RDP":3389,"ICMP":0}.get(proto,80)
            is_bad = random.random() < 0.25
            status = "block" if is_bad else ("warn" if random.random() < 0.1 else "allow")
            reason = random.choice(BAD_REASONS) if is_bad else ""

            STATE.packets_total += 1
            STATE.proto_stats[proto] += 1
            if is_bad:
                STATE.packets_blocked += 1
                STATE.ip_hit_counter[src] += 1
                STATE.geo_hits[entry["country"]] += 1
            else:
                STATE.packets_allowed += 1
            STATE.bytes_in += random.randint(40, 1500)

            # Offset stable par IP pour scatter sur la carte
            parts = [int(x) for x in src.split('.')]
            lat_off = ((parts[2]*17 + parts[3]*31) % 100) / 100 * 2 - 1
            lon_off = ((parts[2]*13 + parts[3]*7)  % 100) / 100 * 3 - 1.5

            STATE.recent_packets.appendleft({
                "t":       datetime.now().strftime("%H:%M:%S"),
                "src":     src, "dst": "192.168.1.1",
                "sport":   random.randint(1024,65535), "dport": port,
                "proto":   proto, "size": f"{random.randint(40,1500)}B",
                "status":  status, "reason": reason, "flags": "S" if proto=="TCP" else "",
                "country": entry["country"],
                "city":    entry["city"],
                "lat":     entry["lat"] + lat_off,
                "lon":     entry["lon"] + lon_off,
                "location": f"{entry['city']}, {GEO_COUNTRY_NAMES.get(entry['country'], entry['country'])}",
            })
            if is_bad and random.random() < 0.3:
                STATE.threats.appendleft({
                    "id":          int(time.time()*1000),
                    "timestamp":   datetime.now().isoformat(),
                    "src_ip":      src,
                    "type":        reason or "Activité suspecte",
                    "description": f"Détecté depuis {src} ({entry['city']})",
                    "severity":    random.choice(["critical","high","med","low"]),
                    "blocked":     True,
                })
            if random.random() < 0.05:
                STATE.dpi_alerts.appendleft({
                    "ts": datetime.now().strftime("%H:%M:%S"),
                    "src": src,
                    "type": random.choice(["attack","sensitive"]),
                    "detail": random.choice(["SQL Injection","XSS","password","cookie"]),
                    "masked": random.choice([True, False]),
                })

async def rest_api_handler(reader, writer):
    """Serveur REST API HTTP simple — GET /api/state, /api/threats, /api/blocked"""
    try:
        request = await reader.read(1024)
        req_str = request.decode(errors="ignore")
        path = req_str.split(" ")[1] if " " in req_str else "/"

        cors_headers = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST\r\n"

        if path == "/api/state":
            body = json.dumps(build_state_message())
        elif path == "/api/threats":
            body = json.dumps(list(STATE.threats))
        elif path == "/api/blocked":
            body = json.dumps(list(BLOCKED_IPS))
        elif path == "/api/history":
            body = json.dumps(history_get("day"))
        elif path == "/api/summary":
            body = json.dumps(history_summary("week"))
        elif path == "/api/fingerprints":
            body = json.dumps(_os_fingerprints)
        elif path == "/api/rate_stats":
            body = json.dumps(get_rate_limit_stats())
        elif path.startswith("/api/ip/"):
            ip = path.split("/api/ip/")[1]
            body = json.dumps({
                "ip":       ip,
                "blocked":  ip in BLOCKED_IPS,
                "hits":     STATE.ip_hit_counter.get(ip, 0),
                "risk":     STATE.ip_risk_scores.get(ip, 0),
                "intel":    STATE.ip_intel.get(ip, {}),
                "os":       _os_fingerprints.get(ip, {}),
                "geo":      _geo_city_cache.get(ip, {}),
            })
        elif path == "/api/status":
            body = json.dumps({
                "version":         "2.3.0",
                "uptime":          time.time(),
                "packets_total":   STATE.packets_total,
                "packets_blocked": STATE.packets_blocked,
                "threats_count":   len(STATE.threats),
                "blocked_ips":     len(BLOCKED_IPS),
                "blacklist_size":  len(COMMUNITY_BLACKLIST),
                "suricata_rules":  SURICATA_LOADED,
                "honeypot":        HONEYPOT_ENABLED,
                "demo_mode":       not HAS_SCAPY,
            })
        else:
            body = json.dumps({"error": "Not found", "endpoints": [
                "/api/state", "/api/threats", "/api/blocked",
                "/api/history", "/api/summary", "/api/fingerprints",
                "/api/rate_stats", "/api/ip/<ip>", "/api/status"
            ]})

        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors_headers}Content-Length: {len(body.encode())}\r\n\r\n{body}"
        writer.write(response.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def main_async(interface: str):
    threading.Thread(target=start_capture, args=(interface,), daemon=True).start()
    log.info(f"[WS] Serveur WebSocket sur ws://localhost:{CFG.ws_port}")

    # Initialiser les utilisateurs
    load_users()

    # Démarrage de la blacklist communautaire en arrière-plan
    threading.Thread(target=update_community_blacklist, daemon=True).start()

    # Générer certificat SSL si pas encore fait
    has_ssl = generate_self_signed_cert()

    # Serveur d'authentification
    if has_ssl:
        try:
            import ssl as ssl_mod
            ssl_ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            auth_srv = await asyncio.start_server(auth_server_handler, "0.0.0.0", 8443, ssl=ssl_ctx)
            log.info("[AUTH] Serveur HTTPS sur https://localhost:8443")
            HTTP_PORT = 8443
        except Exception as e:
            log.warning(f"[SSL] Erreur SSL: {e} — fallback HTTP")
            auth_srv = await asyncio.start_server(auth_server_handler, "0.0.0.0", 8080)
            log.info("[AUTH] Serveur HTTP sur http://localhost:8080")
            HTTP_PORT = 8080
    else:
        auth_srv = await asyncio.start_server(auth_server_handler, "0.0.0.0", 8080)
        log.info("[AUTH] Serveur HTTP sur http://localhost:8080")
        HTTP_PORT = 8080

    tasks = []
    if HAS_WS:
        ws_server = websockets.serve(ws_handler, "localhost", CFG.ws_port)
        tasks.append(ws_server)

    # REST API (port 8766)
    if CFG.__dict__.get("api_enabled", False) or "--api" in sys.argv:
        log.info("[API] Serveur REST sur http://localhost:8766")
        api_server = asyncio.start_server(rest_api_handler, "localhost", 8766)
        tasks.append(api_server)

    if tasks:
        await asyncio.gather(*[asyncio.ensure_future(s) for s in tasks], return_exceptions=True)
        log.info("[WS] Serveur démarré — en attente de connexions")
        async with auth_srv:
            await broadcast_state()
    else:
        async with auth_srv:
            while True:
                await asyncio.sleep(1)
                snapshot_traffic()

SETTINGS_FILE = "netguard_settings.json"
USERS_FILE    = "netguard_users.json"
CERT_FILE     = "netguard_cert.pem"
KEY_FILE      = "netguard_key.pem"

# ═══════════════════════════════════════════════════════════════════════════
# v3.0.0 — AUTHENTIFICATION + HTTPS + MULTI-UTILISATEURS
# ═══════════════════════════════════════════════════════════════════════════

import hashlib
import secrets
import base64

# Rôles disponibles
ROLES = {
    "admin":    {"label": "Administrateur", "can_block": True,  "can_config": True,  "can_view": True},
    "operator": {"label": "Opérateur",      "can_block": True,  "can_config": False, "can_view": True},
    "viewer":   {"label": "Lecteur",        "can_block": False, "can_config": False, "can_view": True},
}

# Sessions actives: token -> {user, role, expires}
_sessions: dict = {}
SESSION_DURATION = 3600 * 8  # 8 heures

def _hash_password(password: str, salt: str = "") -> str:
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}:{base64.b64encode(h).decode()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split(":", 1)
        return _hash_password(password, salt) == stored
    except Exception:
        return False

def load_users() -> dict:
    """Charge les utilisateurs depuis le fichier JSON"""
    if not os.path.exists(USERS_FILE):
        # Créer l'admin par défaut
        default_users = {
            "admin": {
                "password": _hash_password("netguard2024"),
                "role":     "admin",
                "name":     "Administrateur",
                "created":  datetime.now().isoformat(),
            }
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)
        log.info("[AUTH] Fichier utilisateurs créé — admin/netguard2024")
        return default_users
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "user":    username,
        "role":    role,
        "expires": time.time() + SESSION_DURATION,
    }
    return token

def verify_session(token: str) -> Optional[dict]:
    if not token or token not in _sessions:
        return None
    session = _sessions[token]
    if time.time() > session["expires"]:
        del _sessions[token]
        return None
    session["expires"] = time.time() + SESSION_DURATION  # Refresh
    return session

def cleanup_sessions():
    expired = [t for t, s in _sessions.items() if time.time() > s["expires"]]
    for t in expired:
        del _sessions[t]

def generate_self_signed_cert():
    """Génère un certificat SSL auto-signé pour HTTPS"""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    try:
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-nodes",
            "-subj", "/CN=NetGuard Pro/O=NetGuard/C=CA"
        ], capture_output=True, timeout=30)
        if result.returncode == 0:
            log.info(f"[SSL] Certificat auto-signé généré → {CERT_FILE}")
            return True
        else:
            log.warning("[SSL] openssl non disponible — HTTPS désactivé")
            return False
    except Exception as e:
        log.warning(f"[SSL] Erreur génération certificat: {e}")
        return False

# ── Serveur HTTP d'authentification (port 8080) ────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>NetGuard Pro — Connexion</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f0f13;--bg2:#16161d;--bg4:#22222f;--border:#ffffff1a;--text:#e8e8f0;--text2:#9090a8;--blue:#4d9fff;--red:#ff4d6a}
body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:36px 40px;width:360px}
.logo{text-align:center;margin-bottom:28px}
.logo h1{font-size:22px;font-weight:600}
.logo h1 span{background:linear-gradient(90deg,#4d9fff,#b47dff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo p{font-size:12px;color:var(--text2);margin-top:4px}
.field{margin-bottom:16px}
label{display:block;font-size:12px;color:var(--text2);margin-bottom:6px}
input{width:100%;background:var(--bg4);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:7px;font-size:14px;outline:none}
input:focus{border-color:var(--blue)}
.btn{width:100%;background:var(--blue);color:#fff;border:none;padding:11px;border-radius:7px;font-size:14px;font-weight:500;cursor:pointer;margin-top:8px;transition:.15s}
.btn:hover{background:#3a8ee8}
.error{background:#3d1220;border:1px solid #ff4d6a44;color:var(--red);padding:10px 14px;border-radius:6px;font-size:12px;margin-bottom:16px;display:none}
.footer{text-align:center;font-size:11px;color:var(--text2);margin-top:20px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1><span>Net</span>Guard Pro</h1>
    <p>Cybersécurité avancée</p>
  </div>
  <div class="error" id="err">Identifiants incorrects</div>
  <form onsubmit="login(event)">
    <div class="field">
      <label>Nom d'utilisateur</label>
      <input type="text" id="u" placeholder="admin" autocomplete="username" required>
    </div>
    <div class="field">
      <label>Mot de passe</label>
      <input type="password" id="p" placeholder="••••••••" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">Se connecter →</button>
  </form>
  <div class="footer">NetGuard Pro v3.0 — Accès sécurisé</div>
</div>
<script>
async function login(e) {
  e.preventDefault();
  const r = await fetch('/auth/login', {method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value, password:document.getElementById('p').value})});
  const d = await r.json();
  if (d.ok) {
    localStorage.setItem('ng_token', d.token);
    localStorage.setItem('ng_user', d.user);
    localStorage.setItem('ng_role', d.role);
    window.location.href = 'netguard_dashboard.html';
  } else {
    document.getElementById('err').style.display = 'block';
  }
}
</script>
</body>
</html>"""

async def auth_server_handler(reader, writer):
    """Serveur HTTP d'authentification sur port 8080"""
    try:
        request = await reader.read(4096)
        req_str = request.decode(errors="ignore")
        lines   = req_str.split("\r\n")
        method, path = lines[0].split(" ")[:2] if lines else ("GET", "/")

        cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\n"

        if method == "OPTIONS":
            writer.write(f"HTTP/1.1 200 OK\r\n{cors}\r\n".encode())
        elif path == "/auth/login" and method == "POST":
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                data     = json.loads(body)
                username = data.get("username", "").strip()
                password = data.get("password", "")
                users    = load_users()

                if username in users and _verify_password(password, users[username]["password"]):
                    role  = users[username].get("role", "viewer")
                    token = create_session(username, role)
                    log.info(f"[AUTH] Connexion réussie: {username} ({role})")
                    audit_log(username, "LOGIN", "", f"Rôle: {role}", "")
                    resp  = json.dumps({"ok": True, "token": token, "user": username, "role": role, "name": users[username].get("name","")})
                else:
                    log.warning(f"[AUTH] Échec connexion: {username}")
                    resp  = json.dumps({"ok": False, "error": "Identifiants incorrects"})
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/logout" and method == "POST":
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                token = json.loads(body).get("token","")
                if token in _sessions:
                    del _sessions[token]
            except Exception:
                pass
            resp = json.dumps({"ok": True})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/verify" and method == "POST":
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                token   = json.loads(body).get("token","")
                session = verify_session(token)
                resp    = json.dumps({"ok": bool(session), **(session or {})})
            except Exception:
                resp = json.dumps({"ok": False})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/users" and method == "GET":
            # Lister les utilisateurs (admin seulement — vérifié côté client)
            users = load_users()
            safe  = {u: {"role": d["role"], "name": d.get("name",""), "created": d.get("created","")} for u, d in users.items()}
            resp  = json.dumps(safe)
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/users" and method == "POST":
            # Créer/modifier un utilisateur
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                data  = json.loads(body)
                users = load_users()
                uname = data.get("username","").strip()
                if uname and data.get("password") and data.get("role") in ROLES:
                    users[uname] = {
                        "password": _hash_password(data["password"]),
                        "role":     data["role"],
                        "name":     data.get("name", uname),
                        "created":  datetime.now().isoformat(),
                    }
                    save_users(users)
                    log.info(f"[AUTH] Utilisateur créé/modifié: {uname} ({data['role']})")
                    resp = json.dumps({"ok": True})
                else:
                    resp = json.dumps({"ok": False, "error": "Données invalides"})
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/users/delete" and method == "POST":
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                uname = json.loads(body).get("username","")
                users = load_users()
                if uname in users and uname != "admin":
                    del users[uname]
                    save_users(users)
                    resp = json.dumps({"ok": True})
                else:
                    resp = json.dumps({"ok": False, "error": "Impossible de supprimer l'admin"})
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/auth/change-password" and method == "POST":
            body = req_str.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in req_str else "{}"
            try:
                data        = json.loads(body)
                token       = data.get("token", "")
                old_pw      = data.get("old_password", "")
                new_pw      = data.get("new_password", "")
                session     = verify_session(token)
                if not session:
                    resp = json.dumps({"ok": False, "error": "Session invalide"})
                elif len(new_pw) < 8:
                    resp = json.dumps({"ok": False, "error": "Mot de passe trop court (8 caractères minimum)"})
                else:
                    users    = load_users()
                    username = session["user"]
                    if _verify_password(old_pw, users[username]["password"]):
                        users[username]["password"] = _hash_password(new_pw)
                        save_users(users)
                        log.info(f"[AUTH] Mot de passe changé: {username}")
                        resp = json.dumps({"ok": True})
                    else:
                        resp = json.dumps({"ok": False, "error": "Ancien mot de passe incorrect"})
            except Exception as e:
                resp = json.dumps({"ok": False, "error": str(e)})
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(resp.encode())}\r\n\r\n{resp}".encode())

        elif path == "/" or path == "/login":
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{cors}Content-Length: {len(LOGIN_HTML.encode())}\r\n\r\n{LOGIN_HTML}".encode())

        else:
            body = json.dumps({"error": "Not found"})
            writer.write(f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n{cors}Content-Length: {len(body.encode())}\r\n\r\n{body}".encode())

        await writer.drain()
    except Exception as e:
        log.debug(f"[AUTH] Erreur requête: {e}")
    finally:
        writer.close()
HISTORY_FILE  = "netguard_history.json"
AUDIT_FILE    = "netguard_audit.log"

def audit_log(user: str, action: str, target: str = "", details: str = "", ip: str = ""):
    """Enregistre une action dans le log d'audit"""
    entry = {
        "ts":      datetime.now().isoformat(),
        "user":    user,
        "action":  action,
        "target":  target,
        "details": details,
        "ip":      ip,
    }
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error(f"[AUDIT] Erreur écriture: {e}")
    log.info(f"[AUDIT] {user} — {action} {target}")

def audit_get(limit: int = 200) -> list:
    """Retourne les dernières entrées du log d'audit"""
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line.strip()))
            except Exception:
                pass
        return list(reversed(entries))
    except Exception:
        return []

# ═══════════════════════════════════════════════════════════════════════════
# BACKUP AUTOMATIQUE
# ═══════════════════════════════════════════════════════════════════════════

BACKUP_DIR = "backups"
_last_backup: float = 0
BACKUP_INTERVAL = 3600 * 24  # 24 heures

def run_backup():
    """Sauvegarde automatique des données importantes"""
    global _last_backup
    if time.time() - _last_backup < BACKUP_INTERVAL:
        return
    try:
        import zipfile
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_path = os.path.join(BACKUP_DIR, f"netguard_backup_{ts}.zip")
        files_to_backup = [
            SETTINGS_FILE, HISTORY_FILE, USERS_FILE,
            AUDIT_FILE, "netguard_cert.pem",
        ]
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files_to_backup:
                if os.path.exists(f):
                    zf.write(f)
        # Garder seulement les 7 derniers backups
        backups = sorted([
            os.path.join(BACKUP_DIR, f)
            for f in os.listdir(BACKUP_DIR)
            if f.startswith("netguard_backup_") and f.endswith(".zip")
        ])
        for old in backups[:-7]:
            os.remove(old)
        _last_backup = time.time()
        log.info(f"[BACKUP] Sauvegarde créée → {zip_path}")
        audit_log("système", "BACKUP", zip_path, f"{len(files_to_backup)} fichiers")
    except Exception as e:
        log.error(f"[BACKUP] Erreur: {e}")

# ─── Historique persistant ─────────────────────────────────────────────────
def history_append(threat: dict):
    """Ajoute une menace à l'historique persistant"""
    try:
        history = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        history.append({
            "ts":       threat.get("timestamp", datetime.now().isoformat()),
            "type":     threat.get("type", ""),
            "ip":       threat.get("src_ip", ""),
            "country":  threat.get("country", ""),
            "severity": threat.get("severity", ""),
            "desc":     threat.get("description", ""),
            "blocked":  threat.get("blocked", False),
        })
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False)
    except Exception as e:
        log.error(f"[HISTORY] Erreur sauvegarde: {e}")

def history_get(period: str = "all") -> list:
    """Retourne l'historique filtré par période"""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        if period == "all":
            return history
        now = datetime.now()
        cutoffs = {
            "hour":  now - __import__("datetime").timedelta(hours=1),
            "day":   now - __import__("datetime").timedelta(days=1),
            "week":  now - __import__("datetime").timedelta(weeks=1),
            "month": now - __import__("datetime").timedelta(days=30),
            "year":  now - __import__("datetime").timedelta(days=365),
        }
        from datetime import timedelta
        cutoff_map = {
            "hour":  datetime.now() - timedelta(hours=1),
            "day":   datetime.now() - timedelta(days=1),
            "week":  datetime.now() - timedelta(weeks=1),
            "month": datetime.now() - timedelta(days=30),
            "year":  datetime.now() - timedelta(days=365),
        }
        cutoff = cutoff_map.get(period)
        if not cutoff:
            return history
        return [h for h in history if h.get("ts","") >= cutoff.isoformat()]
    except Exception:
        return []

def history_clear(period: str = "all"):
    """Efface l'historique (tout ou par période)"""
    if period == "all" or not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
        log.info("[HISTORY] Historique effacé complètement")
        return
    try:
        from datetime import timedelta
        cutoff_map = {
            "hour":  datetime.now() - timedelta(hours=1),
            "day":   datetime.now() - timedelta(days=1),
            "week":  datetime.now() - timedelta(weeks=1),
            "month": datetime.now() - timedelta(days=30),
        }
        cutoff = cutoff_map.get(period)
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        kept = [h for h in history if cutoff and h.get("ts","") < cutoff.isoformat()]
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(kept, f, ensure_ascii=False)
        log.info(f"[HISTORY] Effacé période {period} — {len(history)-len(kept)} entrées supprimées")
    except Exception as e:
        log.error(f"[HISTORY] Erreur effacement: {e}")

def history_summary(period: str = "week") -> dict:
    """Génère un résumé analytique pour la période donnée"""
    data = history_get(period)
    if not data:
        return {"period": period, "total": 0, "by_type": {}, "by_country": {}, "by_severity": {}, "by_day": {}, "top_ips": {}}

    by_type     = {}
    by_country  = {}
    by_severity = {}
    by_day      = {}
    by_ip       = {}

    for h in data:
        t  = h.get("type","Autre")
        c  = h.get("country","?")
        s  = h.get("severity","low")
        ip = h.get("ip","")
        d  = h.get("ts","")[:10]

        by_type[t]        = by_type.get(t, 0) + 1
        by_country[c]     = by_country.get(c, 0) + 1
        by_severity[s]    = by_severity.get(s, 0) + 1
        by_day[d]         = by_day.get(d, 0) + 1
        if ip: by_ip[ip]  = by_ip.get(ip, 0) + 1

    top_ips = dict(sorted(by_ip.items(), key=lambda x: -x[1])[:10])

    return {
        "period":      period,
        "total":       len(data),
        "blocked":     sum(1 for h in data if h.get("blocked")),
        "by_type":     dict(sorted(by_type.items(),    key=lambda x: -x[1])[:10]),
        "by_country":  dict(sorted(by_country.items(), key=lambda x: -x[1])[:12]),
        "by_severity": by_severity,
        "by_day":      dict(sorted(by_day.items())),
        "top_ips":     top_ips,
    }

# ═══════════════════════════════════════════════════════════════════════════
# v2.1.0 — ALERTES EMAIL + NOTIFICATIONS WINDOWS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AlertConfig:
    email_enabled:    bool  = False
    email_from:       str   = ""
    email_to:         str   = ""
    email_smtp:       str   = "smtp.gmail.com"
    email_port:       int   = 587
    email_password:   str   = ""
    email_min_sev:    str   = "high"     # critical, high, med
    toast_enabled:    bool  = True
    toast_min_sev:    str   = "high"
    alert_cooldown:   int   = 60         # secondes entre 2 alertes pour la même IP

ALERT_CFG = AlertConfig()
_alert_last_sent: dict = {}  # ip -> timestamp dernière alerte

def _should_alert(ip: str, severity: str, min_sev: str) -> bool:
    """Vérifie si on doit envoyer une alerte (cooldown + sévérité)"""
    sev_order = {"critical": 4, "high": 3, "med": 2, "medium": 2, "low": 1}
    if sev_order.get(severity, 0) < sev_order.get(min_sev, 3):
        return False
    last = _alert_last_sent.get(ip, 0)
    if time.time() - last < ALERT_CFG.alert_cooldown:
        return False
    _alert_last_sent[ip] = time.time()
    return True

def send_alert(threat: dict):
    """Point d'entrée principal — envoie email + toast si configuré"""
    ip       = threat.get("src_ip", "?")
    severity = threat.get("severity", "low")
    ttype    = threat.get("type", "Menace")
    desc     = threat.get("description", "")
    country  = threat.get("country", "")
    ts       = threat.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")

    # Toast Windows (non bloquant)
    if ALERT_CFG.toast_enabled and _should_alert(ip + "_toast", severity, ALERT_CFG.toast_min_sev):
        threading.Thread(
            target=_send_toast,
            args=(ip, severity, ttype, country),
            daemon=True
        ).start()

    # Email (non bloquant)
    if ALERT_CFG.email_enabled and ALERT_CFG.email_to and _should_alert(ip + "_email", severity, ALERT_CFG.email_min_sev):
        threading.Thread(
            target=_send_email_alert,
            args=(ip, severity, ttype, desc, country, ts),
            daemon=True
        ).start()

def _send_toast(ip: str, severity: str, ttype: str, country: str):
    """Notification Windows toast via PowerShell"""
    if os.name != "nt":
        return
    try:
        flags = {
            "critical": "🚨 CRITIQUE",
            "high":     "⚠️ ÉLEVÉ",
            "med":      "⚡ MOYEN",
            "medium":   "⚡ MOYEN",
            "low":      "ℹ️ INFO",
        }
        flag = flags.get(severity, "⚠️")
        title = f"NetGuard Pro — {flag}"
        body  = f"{ttype}\nIP: {ip} {country}"

        ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$notify.BalloonTipTitle = "{title}"
$notify.BalloonTipText = "{body}"
$notify.Visible = $True
$notify.ShowBalloonTip(5000)
Start-Sleep -Seconds 6
$notify.Dispose()
"""
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        log.info(f"[TOAST] Notification envoyée: {ttype} — {ip}")
    except Exception as e:
        log.error(f"[TOAST] Erreur: {e}")

def _send_email_alert(ip: str, severity: str, ttype: str, desc: str, country: str, ts: str):
    """Envoie un email d'alerte via SMTP"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        sev_emoji = {"critical":"🚨","high":"⚠️","med":"⚡","medium":"⚡","low":"ℹ️"}
        emoji = sev_emoji.get(severity, "⚠️")

        subject = f"{emoji} NetGuard Pro — {severity.upper()} — {ttype}"

        html = f"""
<html><body style="font-family:Arial,sans-serif;background:#0f0f13;color:#e8e8f0;padding:20px">
<div style="max-width:500px;margin:0 auto;background:#16161d;border-radius:10px;overflow:hidden">
  <div style="background:{'#3d1220' if severity in ('critical','high') else '#3d2800'};padding:16px 20px">
    <h2 style="margin:0;color:{'#ff4d6a' if severity in ('critical','high') else '#ffb347'}">{emoji} NetGuard Pro — Alerte {severity.upper()}</h2>
  </div>
  <div style="padding:20px">
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="padding:8px 0;color:#9090a8;width:140px">Type d'attaque</td><td style="color:#e8e8f0;font-weight:600">{ttype}</td></tr>
      <tr><td style="padding:8px 0;color:#9090a8">IP source</td><td style="color:#4d9fff;font-family:monospace;font-size:14px">{ip}</td></tr>
      <tr><td style="padding:8px 0;color:#9090a8">Pays</td><td style="color:#e8e8f0">{country or 'Inconnu'}</td></tr>
      <tr><td style="padding:8px 0;color:#9090a8">Description</td><td style="color:#e8e8f0">{desc}</td></tr>
      <tr><td style="padding:8px 0;color:#9090a8">Heure</td><td style="color:#e8e8f0;font-family:monospace">{ts}</td></tr>
      <tr><td style="padding:8px 0;color:#9090a8">Statut</td><td style="color:#ff4d6a;font-weight:600">{'🚫 IP bloquée' if ip in BLOCKED_IPS else '⚡ Détectée'}</td></tr>
    </table>
  </div>
  <div style="padding:12px 20px;background:#0f0f13;font-size:11px;color:#5a5a72">
    NetGuard Pro v2.1.0 — Ouvre le dashboard: netguard_dashboard.html
  </div>
</div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = ALERT_CFG.email_from or f"netguard@localhost"
        msg["To"]      = ALERT_CFG.email_to
        msg.attach(MIMEText(f"{ttype}\nIP: {ip}\nPays: {country}\n{desc}\nHeure: {ts}", "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(ALERT_CFG.email_smtp, ALERT_CFG.email_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(ALERT_CFG.email_from, ALERT_CFG.email_password)
            server.sendmail(ALERT_CFG.email_from, ALERT_CFG.email_to, msg.as_string())

        log.info(f"[EMAIL] Alerte envoyée à {ALERT_CFG.email_to}: {ttype} — {ip}")
    except Exception as e:
        log.error(f"[EMAIL] Erreur envoi: {e}")

def save_settings():
    """Sauvegarde les settings dans un fichier JSON"""
    try:
        settings = {
            "rules": {k: v["enabled"] for k, v in RULES.items()},
            "blocked_ips": list(BLOCKED_IPS),
            "geo_blocked_countries": list(GEO_BLOCKED_COUNTRIES),
            "auto_block_enabled": CFG.auto_block_enabled,
            "auto_block_hits": CFG.auto_block_hits,
            "dpi_enabled": CFG.dpi_enabled,
            "dpi_mask_sensitive": CFG.dpi_mask_sensitive,
            "suricata_enabled": SURICATA_ENABLED,
            "alert_email_enabled":  ALERT_CFG.email_enabled,
            "alert_email_from":     ALERT_CFG.email_from,
            "alert_email_to":       ALERT_CFG.email_to,
            "alert_email_smtp":     ALERT_CFG.email_smtp,
            "alert_email_port":     ALERT_CFG.email_port,
            "alert_email_min_sev":  ALERT_CFG.email_min_sev,
            "alert_toast_enabled":  ALERT_CFG.toast_enabled,
            "alert_toast_min_sev":  ALERT_CFG.toast_min_sev,
            "alert_cooldown":       ALERT_CFG.alert_cooldown,
            "detection_params": {
                k: DETECTION_PARAMS[k]["value"]
                for k in DETECTION_PARAMS
            } if 'DETECTION_PARAMS' in globals() else {},
        }
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        log.info(f"[SETTINGS] Sauvegardé → {SETTINGS_FILE}")
    except Exception as e:
        log.error(f"[SETTINGS] Erreur sauvegarde: {e}")

def load_settings():
    """Charge les settings depuis le fichier JSON"""
    global GEO_BLOCKED_COUNTRIES, SURICATA_ENABLED
    if not os.path.exists(SETTINGS_FILE):
        log.info("[SETTINGS] Aucun fichier de settings trouvé — paramètres par défaut")
        return
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)

        # Règles
        for k, enabled in s.get("rules", {}).items():
            if k in RULES:
                RULES[k]["enabled"] = enabled

        # IPs bloquées
        for ip in s.get("blocked_ips", []):
            BLOCKED_IPS.add(ip)

        # Géoblocage
        GEO_BLOCKED_COUNTRIES = set(s.get("geo_blocked_countries", []))

        # Config
        CFG.auto_block_enabled  = s.get("auto_block_enabled", True)
        CFG.auto_block_hits     = s.get("auto_block_hits", 10)
        CFG.dpi_enabled         = s.get("dpi_enabled", True)
        CFG.dpi_mask_sensitive  = s.get("dpi_mask_sensitive", True)
        SURICATA_ENABLED        = s.get("suricata_enabled", True)

        # Alertes
        ALERT_CFG.email_enabled  = s.get("alert_email_enabled", False)
        ALERT_CFG.email_from     = s.get("alert_email_from", "")
        ALERT_CFG.email_to       = s.get("alert_email_to", "")
        ALERT_CFG.email_smtp     = s.get("alert_email_smtp", "smtp.gmail.com")
        ALERT_CFG.email_port     = s.get("alert_email_port", 587)
        ALERT_CFG.email_min_sev  = s.get("alert_email_min_sev", "high")
        ALERT_CFG.toast_enabled  = s.get("alert_toast_enabled", True)
        ALERT_CFG.toast_min_sev  = s.get("alert_toast_min_sev", "high")
        ALERT_CFG.alert_cooldown = s.get("alert_cooldown", 60)

        log.info(f"[SETTINGS] Chargé — {len(BLOCKED_IPS)} IPs bloquées, {len(GEO_BLOCKED_COUNTRIES)} pays géobloqués")
    except Exception as e:
        log.error(f"[SETTINGS] Erreur chargement: {e}")

def main():
    parser = argparse.ArgumentParser(description="NetGuard Pro — Surveillance réseau")
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--port",      type=int, default=8765)
    parser.add_argument("--no-block",  action="store_true")
    parser.add_argument("--demo",      action="store_true")
    parser.add_argument("--api",       action="store_true", help="Activer l'API REST sur port 8766")
    parser.add_argument("--kiosk",     action="store_true", help="Ouvrir le dashboard en mode plein écran")
    args = parser.parse_args()

    CFG.ws_port   = args.port
    CFG.can_block = not args.no_block

    if args.demo:
        global HAS_SCAPY
        HAS_SCAPY = False

    # Mode kiosk — ouvre le dashboard en plein écran
    if args.kiosk:
        dashboard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard_dashboard.html")
        try:
            if platform.system() == "Windows":
                subprocess.Popen([
                    "cmd", "/c", "start", "/max", "msedge",
                    "--kiosk", f"file:///{dashboard}",
                    "--edge-kiosk-type=fullscreen"
                ])
            else:
                subprocess.Popen(["chromium-browser", "--kiosk", f"file://{dashboard}"])
            log.info("[KIOSK] Dashboard ouvert en mode plein écran")
        except Exception as e:
            log.warning(f"[KIOSK] Impossible d'ouvrir le navigateur: {e}")

    if args.api:
        log.info("[API] REST API activée sur http://localhost:8766")

    interface = args.interface
    if interface == "auto":
        interface = auto_select_interface()
        log.info(f"[AUTO] Interface sélectionnée: {interface}")

    # Créer les dossiers nécessaires
    os.makedirs(CFG.record_dir, exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    # Charger les settings sauvegardés
    load_settings()

    print("""
╔══════════════════════════════════════════════╗
║      NetGuard Pro v2.0.0 — Démarrage        ║
╠══════════════════════════════════════════════╣
║  IDS • DPI • Honeypot • DNS BH • Scan LAN  ║
║  Score risque • ASN • Timeline • Geo        ║
╚══════════════════════════════════════════════╝
""")
    log.info("[MODE] Protection active" if CFG.can_block else "[MODE] Surveillance uniquement")
    if not HAS_SCAPY:
        log.info("[INFO] Npcap non installé — mode DEMO actif (trafic simulé). Installe Npcap pour la capture réelle.")
    try:
        asyncio.run(main_async(interface))
    except KeyboardInterrupt:
        log.info("Arrêt de NetGuard Pro — sauvegarde des settings...")
        save_settings()

if __name__ == "__main__":
    main()
