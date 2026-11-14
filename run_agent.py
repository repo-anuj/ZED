#!/usr/bin/env python3
"""
ZED Standalone Agent Runner
Runs on the endpoint VM to capture telemetry and send it to the remote or local Collector API.
Automatically activates the project virtual environment.
"""

import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"

if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)

import time
import requests
from zed.config import COLLECTOR_URL
from zed.models import TelemetryEvent, BehaviorFeatures
from zed.agent.monitor import AgentMonitor

def forward_event(event: TelemetryEvent):
    try:
        requests.post(f"{COLLECTOR_URL}/api/v1/event", json=event.to_dict(), timeout=1.0)
    except Exception:
        pass

def forward_features(features: BehaviorFeatures):
    pass

def main():
    print(f"""
======================================================================
  [+] ZED ENDPOINT TELEMETRY AGENT
  Forwarding to Collector at: {COLLECTOR_URL}
======================================================================
    """)
    monitor = AgentMonitor(
        event_callback=forward_event,
        feature_callback=forward_features
    )
    monitor.start()
    print("[+] Agent monitoring active. Press Ctrl+C to terminate.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n[-] Agent stopped.")

if __name__ == "__main__":
    main()
