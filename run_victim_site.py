#!/usr/bin/env python3
"""
ZED Victim Demo Website Launcher
Starts the simulated "Apex Community Health Clinic" portal on port 8080.
Designed for demonstrating attacks and EDR defense to non-technical observers and evaluators.
"""

import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"

if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

victim_app = FastAPI(title="Apex Health Clinic Portal (Victim Demo)")

DEMO_HTML = BASE_DIR / "zed" / "web" / "templates" / "demo_portal.html"

@victim_app.get("/", response_class=HTMLResponse)
async def serve_victim_portal():
    with open(DEMO_HTML, "r") as f:
        return HTMLResponse(f.read())

def main():
    print("""
======================================================================
  🏥 APEX COMMUNITY HEALTH CLINIC - TARGET PORTAL (DEMO SINK)
  Designed for Non-Technical Audiences & Project Evaluations
======================================================================
[+] Victim Portal URL: http://127.0.0.1:8080
[+] Explains how attacks happen and what the limitations of ZED are.
======================================================================
    """)
    uvicorn.run(victim_app, host="127.0.0.1", port=8080, log_level="warning")

if __name__ == "__main__":
    main()
