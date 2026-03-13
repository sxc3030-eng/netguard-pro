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
    "block_port_scan":     {"enabled": True,  "label": "Bloquer scan de ports",   "hits": 0},
    "block_ssh_external":  {"enabled": True,  "label": "Bloquer SSH externe",     "hits": 0},
    "block_rdp_public":    {"enabled": True,  "label": "Bloquer RDP public",      "hits": 0},
    "block_tor_exits":     {"enabled": True,  "label": "Bloquer Tor exit nodes",  "hits": 0},
    "block_p2p":           {"enabled": True,  "label": "Bloquer P2P/Torrent",     "hits": 0},
    "block_syn_flood":     {"enabled": True,  "label": "Bloquer SYN Flood",       "hits": 0},
    "block_brute_force":   {"enabled": True,  "label": "Bloquer Brute Force",     "hits": 0},
    "alert_geo":           {"enabled": True,  "label": "Alerter trafic suspect",  "hits": 0},
}

# ─── Listes noires ─────────────────────────────────────────────────────────
TOR_EXIT_NODES: set = set()   # chargées depuis fichier ou API
BLOCKED_IPS:    set = set()   # IPs bloquées dynamiquement
BLOCKED_NETS:   list = []     # Réseaux bloqués

# Plages IP connues comme malveillantes (exemples)
KNOWN_BAD_RANGES = [
    "185.220.0.0/16",   # Tor relays connus
    "162.247.74.0/24",  # Tor exit nodes
]

# Ports P2P/BitTorrent
P2P_PORTS = set(range(6881, 6890)) | {51413, 1337, 2710}

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
        self._port_scan_tracker    = defaultdict(list)  # ip -> [(ts, port)]
        self._brute_force_tracker  = defaultdict(list)  # ip -> [timestamps]
        self._syn_flood_tracker    = defaultdict(list)  # ip -> [timestamps]
        self._dns_tracker          = defaultdict(list)  # ip -> [timestamps]

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
    threat_added = None

    with STATE.lock:
        STATE.packets_total += 1
        STATE.proto_stats[proto] += 1

        # Direction (approximation)
        if is_private(dst_ip):
            STATE.bytes_in += pkt_len
        else:
            STATE.bytes_out += pkt_len

        # ── Règles de blocage ─────────────────────────────────────────────

        # 1. IP déjà bloquée
        if src_ip in BLOCKED_IPS:
            decision = "block"
            reason   = "IP blacklistée"

        # 2. Plages malveillantes connues
        elif is_in_bad_range(src_ip):
            decision = "block"
            reason   = "IP dans plage malveillante connue"
            block_ip_os(src_ip, reason)

        # 3. Ports toujours bloqués (depuis IP externe)
        elif not is_private(src_ip) and dst_port in CFG.always_block_ports:
            decision = "block"
            reason   = f"Port {dst_port} toujours bloqué"
            RULES["block_rdp_public"]["hits"] += (1 if dst_port == 3389 else 0)

        # 4. SSH/RDP depuis IP externe
        elif (not is_private(src_ip) and
              dst_port in CFG.sensitive_ports and
              RULES["block_ssh_external"]["enabled"]):
            decision = "block"
            reason   = f"Accès port sensible ({dst_port}) depuis IP externe"
            RULES["block_ssh_external"]["hits"] += 1

        # 5. P2P / BitTorrent
        elif (dst_port in P2P_PORTS or src_port in P2P_PORTS) and RULES["block_p2p"]["enabled"]:
            decision = "block"
            reason   = "Trafic P2P/BitTorrent"
            RULES["block_p2p"]["hits"] += 1

        # ── Détections dynamiques ─────────────────────────────────────────
        else:
            if not is_private(src_ip):
                # Port scan
                scan_reason = detect_port_scan(src_ip, dst_port)
                if scan_reason:
                    decision = "block"
                    reason   = scan_reason
                    threat_added = add_threat(src_ip, "Scan de ports", scan_reason, "high", "block_port_scan")
                    block_ip_os(src_ip, scan_reason)

                # Brute force
                if decision == "allow":
                    bf_reason = detect_brute_force(src_ip, dst_port, is_syn)
                    if bf_reason:
                        decision = "block"
                        reason   = bf_reason
                        threat_added = add_threat(src_ip, "Brute Force", bf_reason, "high", "block_brute_force")
                        block_ip_os(src_ip, bf_reason)

                # SYN flood
                if decision == "allow":
                    syn_reason = detect_syn_flood(src_ip, is_syn)
                    if syn_reason:
                        decision = "block"
                        reason   = syn_reason
                        threat_added = add_threat(src_ip, "SYN Flood", syn_reason, "high", "block_syn_flood")
                        block_ip_os(src_ip, syn_reason)

            # DNS tunneling (LAN ou WAN)
            if decision == "allow" and pkt.haslayer(DNS):
                dns_reason = detect_dns_tunneling(src_ip)
                if dns_reason:
                    decision = "warn"
                    reason   = dns_reason
                    threat_added = add_threat(src_ip, "DNS Tunneling", dns_reason, "med")

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
            "blocked_ips":    list(BLOCKED_IPS)[:50],
            "rules":          rules_out,
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
