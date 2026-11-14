"""
ZED Configuration Module
Defines settings, paths, thresholds, and safe process lists.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# Network & Server Config (Supports 0.0.0.0 for LAN, Docker, and Cloud Deployment)
SERVER_HOST = os.getenv("ZED_HOST", os.getenv("HOST", "0.0.0.0"))
SERVER_PORT = int(os.getenv("ZED_PORT", os.getenv("PORT", 8000)))
COLLECTOR_URL = f"http://{SERVER_HOST if SERVER_HOST != '0.0.0.0' else '127.0.0.1'}:{SERVER_PORT}"
WEBSOCKET_URL = f"ws://{SERVER_HOST if SERVER_HOST != '0.0.0.0' else '127.0.0.1'}:{SERVER_PORT}/ws"

# Database
DB_PATH = BASE_DIR / "zed.db"

# ML Baseline Model
MODEL_PATH = BASE_DIR / "zed" / "engine" / "zed_baseline.joblib"
ML_CONTAMINATION = 0.04          # Expected anomaly rate in normal baseline
ML_N_ESTIMATORS = 100            # Isolation Forest decision trees
ML_WINDOW_SECONDS = 3            # Rolling window for feature aggregation

# Sandbox Directories for Safe Adversary Simulation
SANDBOX_DIR = BASE_DIR / "sandbox_target"
SANDBOX_CRON_DIR = BASE_DIR / "sandbox_cron"

# Ensure sandboxes exist
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_CRON_DIR.mkdir(parents=True, exist_ok=True)

# Protected Critical Process Whitelist (EDR Response will NEVER kill these)
PROTECTED_PROCESS_NAMES = {
    "systemd", "init", "kthreadd", "systemd-journal", "systemd-udevd",
    "dbus-daemon", "Xorg", "cinnamon", "gnome-shell", "pulseaudio",
    "pipewire", "sshd", "login", "sudo", "bash", "zsh", "sh",
    "code", "cursor", "zed_server", "uvicorn", "python3"
}

# Auto-Response Configuration
DEFAULT_AUTO_RESPONSE = True     # True: terminate malicious processes; False: alert only

# Rule Engine Thresholds
RANSOMWARE_TRIGGER_COUNT = 8     # Mass file operations within window
RANSOMWARE_WINDOW_SEC = 3.0
BRUTE_FORCE_TRIGGER_COUNT = 5    # Auth failures within window
BRUTE_FORCE_WINDOW_SEC = 10.0
BEACON_MIN_COUNT = 3             # Number of periodic connections before flagging
BEACON_INTERVAL_TOLERANCE = 1.0  # Max jitter for beaconing detection in seconds
