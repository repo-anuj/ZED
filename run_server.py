#!/usr/bin/env python3
"""
ZED Server Launcher
Starts the FastAPI Collector Daemon, Detection Engines, and embedded Telemetry Monitor.
Automatically activates the project virtual environment.
"""

import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"

# If not running inside the project venv, re-exec with venv python
if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)

import uvicorn
from zed.config import SERVER_HOST, SERVER_PORT
from zed.agent.monitor import AgentMonitor
from zed.engine.dispatcher import dispatcher

def main():
    print("""
======================================================================
  ███████╗███████╗██████╗ 
  ╚══███╔╝██╔════╝██╔══██╗   ZED: ZERO-DAY ENDPOINT DETECTION & RESPONSE
    ███╔╝ █████╗  ██║  ██║   Dual Engine (MITRE Rules + Isolation Forest ML)
   ███╔╝  ██╔══╝  ██║  ██║   Linux Mint 64-bit Profile (8 GB RAM)
  ███████╗███████╗██████╔╝
  ╚══════╝╚══════╝╚═════╝ 
======================================================================
[+] Starting Telemetry Monitor (psutil + inotify)...
    """)

    # Start live telemetry monitor and route into dispatcher
    monitor = AgentMonitor(
        event_callback=dispatcher.handle_event,
        feature_callback=dispatcher.handle_features
    )
    monitor.start()
    print("[+] Telemetry Monitor active: watching processes, sockets, and sandboxes.")
    print(f"[+] Launching Web & WebSocket Daemon at http://{SERVER_HOST}:{SERVER_PORT}")
    print("[+] Open your browser to access the Terminal Interface.")

    try:
        uvicorn.run("zed.collector.server:app", host=SERVER_HOST, port=SERVER_PORT, log_level="warning")
    except KeyboardInterrupt:
        print("\n[-] Shutting down ZED EDR Daemon cleanly...")
        monitor.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()
