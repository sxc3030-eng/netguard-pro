#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   NetGuard Pro v3.0.0 — Installateur Linux
#   Compatible: Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch
# ═══════════════════════════════════════════════════════════════

set -e

VERSION="3.0.0"
INSTALL_DIR="/opt/netguard-pro"
BIN_DIR="/usr/local/bin"
DESKTOP_DIR="/usr/share/applications"
SERVICE_DIR="/etc/systemd/system"
USER_HOME="$HOME"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   NetGuard Pro v${VERSION} — Installation Linux     ║${NC}"
echo -e "${CYAN}║   Suite de Cybersecurite Professionnelle         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Verification root ───────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Ce script necessite les droits root.${NC}"
    echo "    Relancez avec: sudo ./install_linux.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ── Detection de la distribution ────────────────────────────
echo -e "${BLUE}[1/7]${NC} Detection du systeme..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    DISTRO_VERSION="$VERSION_ID"
    echo -e "  ${GREEN}[OK]${NC} $PRETTY_NAME detecte"
else
    DISTRO="unknown"
    echo -e "  ${YELLOW}[!]${NC} Distribution inconnue, tentative d'installation..."
fi

# ── Installation des dependances systeme ─────────────────────
echo ""
echo -e "${BLUE}[2/7]${NC} Installation des dependances systeme..."

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        apt-get update -qq
        apt-get install -y -qq python3 python3-pip python3-venv python3-dev \
            libpcap-dev tcpdump net-tools iptables \
            wireguard wireguard-tools \
            python3-tk 2>/dev/null
        echo -e "  ${GREEN}[OK]${NC} Paquets Debian/Ubuntu installes"
        ;;
    fedora|rhel|centos|rocky|alma)
        dnf install -y -q python3 python3-pip python3-devel \
            libpcap-devel tcpdump net-tools iptables \
            wireguard-tools \
            python3-tkinter 2>/dev/null
        echo -e "  ${GREEN}[OK]${NC} Paquets Fedora/RHEL installes"
        ;;
    arch|manjaro|endeavouros)
        pacman -Sy --noconfirm python python-pip \
            libpcap tcpdump net-tools iptables \
            wireguard-tools \
            tk 2>/dev/null
        echo -e "  ${GREEN}[OK]${NC} Paquets Arch installes"
        ;;
    *)
        echo -e "  ${YELLOW}[!]${NC} Distribution non reconnue. Installez manuellement:"
        echo "      python3 python3-pip libpcap-dev wireguard-tools"
        ;;
esac

# ── Installation de NetGuard Pro ─────────────────────────────
echo ""
echo -e "${BLUE}[3/7]${NC} Installation de NetGuard Pro dans ${INSTALL_DIR}..."

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy all files
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$SCRIPT_DIR/netguard.py" ]; then
    echo "  Copie depuis: $SCRIPT_DIR"
    cp -r "$SCRIPT_DIR"/*.py "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/*.html "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/*.json "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/*.bat "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/*.sh "$INSTALL_DIR/" 2>/dev/null || true

    for dir in sentinel vpnguard cleanguard mailshield honeypot fim recorder strikeback wireguard reports captures; do
        if [ -d "$SCRIPT_DIR/$dir" ]; then
            cp -r "$SCRIPT_DIR/$dir" "$INSTALL_DIR/"
        fi
    done
else
    echo -e "  ${RED}[!]${NC} Fichiers source non trouves dans $SCRIPT_DIR"
    echo "      Placez ce script dans le dossier installer/ du projet."
    exit 1
fi

echo -e "  ${GREEN}[OK]${NC} Fichiers copies"

# ── Installation des dependances Python ──────────────────────
echo ""
echo -e "${BLUE}[4/7]${NC} Installation des dependances Python..."

pip3 install --quiet --break-system-packages \
    websockets scapy pywebview pystray Pillow psutil requests watchdog pefile 2>/dev/null || \
pip3 install --quiet \
    websockets scapy pywebview pystray Pillow psutil requests watchdog pefile 2>/dev/null

echo -e "  ${GREEN}[OK]${NC} Dependances Python installees"

# ── Creation des scripts de lancement ────────────────────────
echo ""
echo -e "${BLUE}[5/7]${NC} Creation des lanceurs..."

# Main launcher
cat > "$BIN_DIR/netguard-pro" << 'LAUNCHER'
#!/bin/bash
cd /opt/netguard-pro
exec python3 /opt/netguard-pro/netguard.py "$@"
LAUNCHER
chmod +x "$BIN_DIR/netguard-pro"

# Sentinel launcher
cat > "$BIN_DIR/sentinel-os" << 'LAUNCHER'
#!/bin/bash
cd /opt/netguard-pro
exec python3 /opt/netguard-pro/sentinel/cortex.py "$@"
LAUNCHER
chmod +x "$BIN_DIR/sentinel-os"

# VPN Guard launcher
cat > "$BIN_DIR/vpnguard" << 'LAUNCHER'
#!/bin/bash
cd /opt/netguard-pro
exec python3 /opt/netguard-pro/vpnguard/vpnguard.py "$@"
LAUNCHER
chmod +x "$BIN_DIR/vpnguard"

# CleanGuard launcher
cat > "$BIN_DIR/cleanguard" << 'LAUNCHER'
#!/bin/bash
cd /opt/netguard-pro
exec python3 /opt/netguard-pro/cleanguard/cleanguard.py "$@"
LAUNCHER
chmod +x "$BIN_DIR/cleanguard"

# Suite launcher (all agents)
cat > "$BIN_DIR/netguard-suite" << 'LAUNCHER'
#!/bin/bash
echo "NetGuard Pro Suite v3.0.0 — Demarrage de tous les agents..."
cd /opt/netguard-pro
python3 /opt/netguard-pro/netguard.py &
sleep 1
python3 /opt/netguard-pro/sentinel/cortex.py &
python3 /opt/netguard-pro/vpnguard/vpnguard.py &
python3 /opt/netguard-pro/cleanguard/cleanguard.py &
python3 /opt/netguard-pro/honeypot/honeypot.py &
python3 /opt/netguard-pro/fim/file_integrity_monitor.py &
python3 /opt/netguard-pro/strikeback/strikeback.py &
python3 /opt/netguard-pro/recorder/recorder.py &
echo "Tous les agents sont lances."
echo "Dashboard: xdg-open /opt/netguard-pro/netguard_dashboard.html"
wait
LAUNCHER
chmod +x "$BIN_DIR/netguard-suite"

echo -e "  ${GREEN}[OK]${NC} Lanceurs crees dans $BIN_DIR"

# ── Creation des fichiers .desktop ───────────────────────────
echo ""
echo -e "${BLUE}[6/7]${NC} Creation des raccourcis d'application..."

cat > "$DESKTOP_DIR/netguard-pro.desktop" << EOF
[Desktop Entry]
Name=NetGuard Pro
Comment=Suite de Cybersecurite Professionnelle
Exec=netguard-pro
Icon=/opt/netguard-pro/netguard_icon.png
Terminal=true
Type=Application
Categories=Network;Security;System;
Keywords=firewall;ids;security;network;
EOF

cat > "$DESKTOP_DIR/sentinel-os.desktop" << EOF
[Desktop Entry]
Name=Sentinel OS
Comment=Orchestrateur Central NetGuard Pro
Exec=sentinel-os
Icon=/opt/netguard-pro/netguard_icon.png
Terminal=true
Type=Application
Categories=Network;Security;System;
EOF

cat > "$DESKTOP_DIR/netguard-suite.desktop" << EOF
[Desktop Entry]
Name=NetGuard Suite
Comment=Lancer toute la suite NetGuard Pro
Exec=netguard-suite
Icon=/opt/netguard-pro/netguard_icon.png
Terminal=true
Type=Application
Categories=Network;Security;System;
EOF

# Copy to user desktop
DESKTOP_PATH="$REAL_HOME/Desktop"
if [ ! -d "$DESKTOP_PATH" ]; then
    DESKTOP_PATH="$REAL_HOME/Bureau"
fi
if [ -d "$DESKTOP_PATH" ]; then
    cp "$DESKTOP_DIR/netguard-pro.desktop" "$DESKTOP_PATH/"
    cp "$DESKTOP_DIR/sentinel-os.desktop" "$DESKTOP_PATH/"
    cp "$DESKTOP_DIR/netguard-suite.desktop" "$DESKTOP_PATH/"
    chmod +x "$DESKTOP_PATH"/*.desktop 2>/dev/null
    chown "$REAL_USER:$REAL_USER" "$DESKTOP_PATH"/*.desktop 2>/dev/null
fi

echo -e "  ${GREEN}[OK]${NC} Raccourcis crees"

# ── Creation des services systemd ────────────────────────────
echo ""
echo -e "${BLUE}[7/7]${NC} Creation des services systemd..."

cat > "$SERVICE_DIR/netguard-pro.service" << EOF
[Unit]
Description=NetGuard Pro — IDS/Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netguard-pro
ExecStart=/usr/bin/python3 /opt/netguard-pro/netguard.py --headless
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > "$SERVICE_DIR/netguard-sentinel.service" << EOF
[Unit]
Description=Sentinel OS — Orchestrateur NetGuard Pro
After=network-online.target netguard-pro.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netguard-pro
ExecStart=/usr/bin/python3 /opt/netguard-pro/sentinel/cortex.py --headless
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo -e "  ${GREEN}[OK]${NC} Services systemd crees"

# ── Permissions ──────────────────────────────────────────────
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
# Settings files need to be writable
chmod 666 "$INSTALL_DIR"/*.json 2>/dev/null || true
chmod 666 "$INSTALL_DIR"/sentinel/*.json 2>/dev/null || true
chmod 666 "$INSTALL_DIR"/vpnguard/*.json 2>/dev/null || true

# Create necessary directories
mkdir -p "$INSTALL_DIR/captures" "$INSTALL_DIR/reports" "$INSTALL_DIR/backups" "$INSTALL_DIR/logs"
chmod 777 "$INSTALL_DIR/captures" "$INSTALL_DIR/reports" "$INSTALL_DIR/backups" "$INSTALL_DIR/logs"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   INSTALLATION REUSSIE !                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Commandes disponibles :${NC}"
echo -e "    ${GREEN}netguard-pro${NC}       — Lancer NetGuard Pro (IDS/Firewall)"
echo -e "    ${GREEN}sentinel-os${NC}        — Lancer Sentinel OS (Orchestrateur)"
echo -e "    ${GREEN}vpnguard${NC}           — Lancer VPN Guard"
echo -e "    ${GREEN}cleanguard${NC}         — Lancer CleanGuard"
echo -e "    ${GREEN}netguard-suite${NC}     — Lancer toute la suite"
echo ""
echo -e "  ${CYAN}Services systemd :${NC}"
echo -e "    sudo systemctl start netguard-pro"
echo -e "    sudo systemctl enable netguard-pro  ${YELLOW}(demarrage auto)${NC}"
echo -e "    sudo systemctl start netguard-sentinel"
echo ""
echo -e "  ${CYAN}Dashboard :${NC}"
echo -e "    xdg-open /opt/netguard-pro/netguard_dashboard.html"
echo ""
echo -e "  ${CYAN}Desinstallation :${NC}"
echo -e "    sudo /opt/netguard-pro/installer/uninstall_linux.sh"
echo ""
