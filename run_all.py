#!/usr/bin/env python3
"""
ZED One-Command Supervisor
Starts the Collector API, Detection Engine, and Agent Monitor together.
"""

import sys
import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"

def main():
    python_exec = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable

    print("""
======================================================================
  ███████╗███████╗██████╗ 
  ╚══███╔╝██╔════╝██╔══██╗   ZED: ZERO-DAY ENDPOINT DETECTION & RESPONSE
    ███╔╝ █████╗  ██║  ██║   College Project - Behavioral EDR System
   ███╔╝  ██╔══╝  ██║  ██║   Linux Mint 64-bit Edition (8 GB RAM Profile)
  ███████╗███████╗██████╔╝
  ╚══════╝╚══════╝╚═════╝ 
======================================================================
[+] Initializing ZED Supervisor...
[+] Python Interpreter: """ + python_exec + """
[+] Web Interface URL:  http://127.0.0.1:8000
======================================================================
    """)

    # Launch run_server.py
    cmd = [python_exec, str(BASE_DIR / "run_server.py")]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[+] ZED Supervisor terminated.")

if __name__ == "__main__":
    main()
