import sys, os, traceback

logfile = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'sentinel_debug.log')
with open(logfile, 'w') as f:
    f.write(f"Python: {sys.executable}\n")
    f.write(f"CWD: {os.getcwd()}\n")
    f.write(f"argv: {sys.argv}\n")
    f.write(f"stdout: {sys.stdout}\n\n")
    
    try:
        f.write("Importing webview... ")
        import webview
        f.write(f"OK\n")
    except Exception as e:
        f.write(f"FAIL: {e}\n")
    
    try:
        f.write("Importing websockets... ")
        import websockets
        f.write(f"OK\n")
    except Exception as e:
        f.write(f"FAIL: {e}\n")
    
    try:
        f.write("Importing psutil... ")
        import psutil
        f.write(f"OK\n")
    except Exception as e:
        f.write(f"FAIL: {e}\n")
    
    try:
        f.write("\nImporting cortex modules...\n")
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        f.write(f"  sys.path[0]: {sys.path[0]}\n")
        
        f.write("  agent_bus... ")
        from agent_bus import AgentBus
        f.write("OK\n")
        
        f.write("  playbook_engine... ")
        from playbook_engine import PlaybookEngine
        f.write("OK\n")
        
        f.write("  threat_intel... ")
        from threat_intel import ThreatIntelFeed
        f.write("OK\n")
        
        f.write("  alert_manager... ")
        from alert_manager import AlertManager
        f.write("OK\n")
    except Exception as e:
        f.write(f"FAIL: {e}\n")
        f.write(traceback.format_exc())
    
    try:
        f.write("\nTrying webview.create_window...\n")
        f.flush()
        
        dashboard = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sentinel_dashboard.html')
        f.write(f"  Dashboard: {dashboard}\n")
        f.write(f"  Dashboard exists: {os.path.exists(dashboard)}\n")
        f.flush()
        
        # Actually try creating a window
        window = webview.create_window("TEST", dashboard, width=400, height=300)
        f.write("  create_window OK, starting...\n")
        f.flush()
        webview.start()
        f.write("  webview.start() returned\n")
    except Exception as e:
        f.write(f"  FAIL: {e}\n")
        f.write(traceback.format_exc())
    
    f.write("\nDONE\n")
