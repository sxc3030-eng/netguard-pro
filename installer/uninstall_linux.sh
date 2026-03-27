#!/bin/bash
# NetGuard Pro v3.0.0 — Desinstallation Linux
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo "Relancez avec: sudo ./uninstall_linux.sh"
    exit 1
fi

echo ""
echo -e "${RED}NetGuard Pro — Desinstallation${NC}"
echo ""

read -p "Etes-vous sur de vouloir desinstaller NetGuard Pro ? (o/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
    echo "Annule."
    exit 0
fi

# Stop services
systemctl stop netguard-pro 2>/dev/null || true
systemctl stop netguard-sentinel 2>/dev/null || true
systemctl disable netguard-pro 2>/dev/null || true
systemctl disable netguard-sentinel 2>/dev/null || true

# Remove services
rm -f /etc/systemd/system/netguard-pro.service
rm -f /etc/systemd/system/netguard-sentinel.service
systemctl daemon-reload

# Remove launchers
rm -f /usr/local/bin/netguard-pro
rm -f /usr/local/bin/sentinel-os
rm -f /usr/local/bin/vpnguard
rm -f /usr/local/bin/cleanguard
rm -f /usr/local/bin/netguard-suite

# Remove .desktop files
rm -f /usr/share/applications/netguard-pro.desktop
rm -f /usr/share/applications/sentinel-os.desktop
rm -f /usr/share/applications/netguard-suite.desktop

# Remove install directory
rm -rf /opt/netguard-pro

echo -e "${GREEN}[OK]${NC} NetGuard Pro a ete desinstalle."
echo ""
