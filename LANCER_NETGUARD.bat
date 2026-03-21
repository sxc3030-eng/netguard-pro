@echo off
cd /d "%~dp0"
pip install scapy websockets
start "" "netguard_dashboard.html"
python netguard.py
pause