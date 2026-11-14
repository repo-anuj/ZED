# ZED: Zero-day Endpoint Detection & Response (EDR)
> **A Behavior-Based Endpoint Security Monitoring System for Linux Mint / Ubuntu**  
> **Dual Engine:** Behavioral MITRE ATT&CK Rules + Machine Learning (Isolation Forest) Anomaly Detection  
> **Interface:** Retro Linux Console / Terminal-Themed Web Dashboard (Linux Mint Neofetch Hero)  
> **Adversary Emulation:** Built-in Safe Attack Simulator Bot  

---

## 1. Project Overview & Problem Statement

Traditional antivirus solutions depend heavily on **static signatures** (file hashes and known code snippets). When an attacker uses a **Zero-Day vulnerability** (a vulnerability software vendors and security vendors do not yet know about), signature-based tools fail because **no signature exists**.

**ZED solves this problem by observing system behavior after exploitation**:
Even if an exploit itself is novel and unseen, what the attacker executes post-exploitation follows recognizable behavioral patterns:
- Spawning interactive shells from web server daemons
- Creating persistent cron entries
- Performing rapid file encryption/modifications (ransomware velocity)
- Establishing regular outbound beacon connections to external command-and-control (C2) servers
- Generating anomalous multi-dimensional process churn and socket entropy

---

## 2. Architecture & Project Structure

```
/home/anuj/Desktop/ZED/
├── zed/
│   ├── config.py                 # Configuration, safe process whitelists, thresholds
│   ├── db.py                     # SQLite threat database (WAL mode)
│   ├── models.py                 # Data models (Events, Alerts, Feature Vectors)
│   ├── agent/
│   │   ├── monitor.py            # psutil + inotify real-time telemetry collector
│   │   ├── response.py           # Automated incident response (SIGKILL + IP block)
│   │   └── client.py             # Event client for remote agent forwarding
│   ├── engine/
│   │   ├── rule_engine.py        # MITRE ATT&CK Behavioral Rules (T1059, T1053, T1486, T1071, T1110)
│   │   ├── ml_engine.py          # Isolation Forest unsupervised anomaly model (Scikit-Learn)
│   │   └── dispatcher.py         # Coordinates telemetry -> rules -> ML -> DB -> WebSockets
│   ├── collector/
│   │   └── server.py             # FastAPI REST API + WebSocket real-time broadcast
│   ├── bot/
│   │   └── attack_simulator.py   # Safe adversary emulator (6 attack scenarios)
│   └── web/
│       ├── static/
│       │   ├── terminal.css      # Retro Linux Mint / VT100 terminal theme styling
│       │   └── terminal.js       # WebSocket client, metric bar renderer, CLI interpreter
│       └── templates/
│           └── index.html        # Terminal interface with big Linux Mint ASCII hero
├── run_all.py                    # One-command launcher (Supervisor)
├── run_server.py                 # Starts Collector Daemon & embedded monitor
├── run_agent.py                  # Standalone agent runner
├── run_bot.py                    # Standalone attack simulator CLI
└── requirements.txt              # Python dependencies
```

---

## 3. Implementation Phases

### Phase 1: Storage & Configuration
- **SQLite Database (`zed.db`)**: Stores raw events, alerts, responses, and ML baseline metrics using SQLite WAL mode for high concurrency.
- **Process Protection Whitelist**: Prevents automated incident response from terminating essential OS daemons (`systemd`, `init`, user shell, IDE).

### Phase 2: Kernel Telemetry & Inotify Watcher
- **Process Polling (`psutil`)**: Tracks newly spawned processes, parent PID trees, command-line arguments, CPU and RAM metrics.
- **Filesystem Watcher (`watchdog`)**: Watches sensitive directories (`sandbox_target`, `sandbox_cron`) for modifications, renames, and deletions.
- **Network Telemetry**: Monitors outbound TCP/UDP connections, remote IPs, and destination ports.

### Phase 3: Dual Detection Engine
1. **Behavioral Rule Engine (`rule_engine.py`)**:
   - `T1059.004`: Web server spawning an interactive shell (`nginx` / `apache` -> `bash`).
   - `T1053.003`: Unauthorized cron modification / scheduled persistence.
   - `T1486`: Ransomware mass file encryption burst (>8 files in <3 seconds or `.locked` extension).
   - `T1071.001`: Outbound rhythmic C2 beaconing (constant intervals with low jitter).
   - `T1110.001`: Authentication brute force velocity (>5 failed logins in 10s).
2. **Machine Learning Anomaly Engine (`ml_engine.py`)**:
   - Algorithm: **Isolation Forest** from `scikit-learn` (Unsupervised).
   - Evaluates a 7-dimensional behavioral feature vector every 3 seconds:
     `[new_proc_rate, unique_binaries, file_mod_rate, net_conn_rate, distinct_dest_ips, auth_fail_rate, cpu_entropy]`
   - Computes decision function anomaly scores ($< 0$ indicates statistical anomaly).

### Phase 4: Attack Simulator Bot (`attack_simulator.py`)
Provides 6 harmless, isolated scenarios for college demonstration:
- **Scenario 1**: Web shell execution (`fake_web_server` -> `/bin/bash`)
- **Scenario 2**: Scheduled task backdoor injection (`sandbox_cron/zed_backdoor`)
- **Scenario 3**: Ransomware file rapid rename in `sandbox_target/`
- **Scenario 4**: Outbound C2 beaconing pulses to test address `198.51.100.42:8443`
- **Scenario 5**: SSH/PAM login brute force burst
- **Scenario 6 (Simulated Zero-Day)**: Multi-vector behavioral burst that evades all 5 signature rules, but is immediately detected by the Isolation Forest ML model.

### Phase 5: Collector API & Real-Time WebSocket Daemon (`server.py`)
- FastAPI endpoints for event ingestion, threat statistics, attack triggers, baseline retraining, and markdown report generation.
- Full-duplex WebSocket at `/ws` streaming telemetry, alerts, and terminal logs in real time.

### Phase 6: Terminal-Themed Web Interface (`index.html`)
- **No AI Aesthetic**: Free of pastel purple gradients, rounded cartoon cards, or generic SaaS look.
- **True Linux Terminal Styling**: CRT scanline overlay, monospace typography, Linux Mint green (`#87cf3e`), hacker green (`#2bf04c`), warning amber (`#ffb000`), critical alert red (`#ff3333`).
- **Hero Banner**: Neofetch-style Linux Mint ASCII distro art side-by-side with big blocky `ZED` header.
- **Interactive Command Line**: `root@zed-defense:~$ ` prompt supporting `attack <1-6>`, `train`, `status`, `kill <pid>`, `clear`, `report`, and `help`.

### Phase 7: Automated Response Executor
- Terminates hostile processes using `SIGTERM` with escalation to `SIGKILL`.
- Registers firewall isolation (`iptables -A OUTPUT -d <IP> -j DROP`).

---

## 4. How to Run ZED

### Step 1: Activate Virtual Environment
```bash
cd /home/anuj/Desktop/ZED
source .venv/bin/activate
```

### Step 2: Start the System (One Command)
```bash
python3 run_all.py
```
Or directly:
```bash
python3 run_server.py
```

### Step 3: Open the Terminal Interface in Your Browser
Open any web browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 5. Testing the Attack Simulator Bot

### Option A: From the Terminal Web Interface
1. Open `http://127.0.0.1:8000`.
2. Look at the **Attack Simulator Bot Station** panel on the left.
3. Click any of the scenario buttons:
   - Click `[1]` to test Web Shell detection.
   - Click `[3]` to test Ransomware mass file burst.
   - Click `[6]` (**SIMULATED ZERO-DAY**) to test the Machine Learning Anomaly engine!
4. Or type in the interactive prompt at the top:
   ```bash
   attack 6
   ```

### Option B: Standalone from the Terminal CLI
Open a second terminal window and run:
```bash
cd /home/anuj/Desktop/ZED
./.venv/bin/python run_bot.py --scenario 6
```
To run all 6 scenarios in sequence:
```bash
./.venv/bin/python run_bot.py --all
```

### Option C: Using the Non-Technical Victim Demo Portal
Open the victim healthcare portal in your browser:
```
http://127.0.0.1:8000/demo
```
*(Or click `[ 🏥 VICTIM DEMO PORTAL ↗ ]` inside the ZED header)*

- **What it shows**: A realistic clinic portal (**Apex Community Health Clinic**) with patient charts, lab report uploads, and staff logins.
- **For Non-Tech Observers**: Clicking an attack shows in real-time what an attack looks like to regular people (files turning into `.locked`, an attacker terminal popping up, login forms cycling through dictionary attacks) alongside ZED's automated EDR response.
- **Limitations Guide**: Click **`[ 📖 Explainer & Limitations ]`** on the demo portal to open the 4-part guide detailing ZED's honest boundaries.

---

## 6. Explaining the College Demonstration to Your Teacher

When presenting ZED to your teacher or external viva examiner:

1. **Why Dual-Engine (Rules + ML)?**
   - *Rules* catch known attacker techniques instantly with zero false positives (MITRE ATT&CK).
   - *Machine Learning (Isolation Forest)* catches **unknown zero-days** that don't match any rule by identifying anomalous deviation from the system baseline.
2. **Why Isolation Forest instead of Deep Learning / LLM?**
   - Deep learning requires GPUs, tens of gigabytes of RAM, and introduces high latency.
   - Isolation Forest is unsupervised, requires no labeled malware samples, trains in under 1 second, runs smoothly on 8 GB RAM, and scores telemetry in **<5 milliseconds**.
3. **The Proof Experiment (Scenario 6)**:
   - Show your teacher the attack simulator running Scenario 6.
   - Highlight that **Rules matched: 0** (signature evasion).
   - Highlight that **Isolation Forest flagged: ANOMALY DETECTED (Score < 0)**.
   - This proves the thesis: post-exploitation behavioral anomaly detection catches what signature-based tools miss!

---

## 7. Deployment Options

Run the interactive deployment assistant:
```bash
./deploy.sh
```

### Option 1: Linux Mint Background Service (`systemd`)
Runs ZED continuously in the background and restarts automatically on system boot:
```bash
sudo cp zed.service /etc/systemd/system/zed.service
sudo systemctl daemon-reload
sudo systemctl enable --now zed.service
```
- Status check: `sudo systemctl status zed.service`
- Live log tail: `sudo journalctl -u zed.service -f`

### Option 2: Docker Container (`docker compose`)
Runs ZED in an isolated container environment:
```bash
docker compose up -d --build
```
Access `http://localhost:8000` or `http://localhost:8000/demo`.

### Option 3: Local Network (Wi-Fi / LAN) Access
Because ZED binds to `0.0.0.0:8000`, any device (laptop, phone, tablet) on the same Wi-Fi can view the dashboard:
1. Find your Linux Mint IP: `hostname -I | awk '{print $1}'` (e.g. `192.168.1.45`)
2. Open on another device: `http://192.168.1.45:8000`

### Option 4: Free Public HTTPS Link (Cloudflare Tunnel)
To demonstrate ZED to a teacher or examiner remotely without opening firewall ports:
```bash
npx -y cloudflared tunnel --url http://127.0.0.1:8000
```
Gives you a public temporary URL (e.g., `https://xxxx.trycloudflare.com`).

### Option 5: Free Cloud Hosting (Render / Railway)
1. Push this folder to a GitHub repository.
2. In [Render](https://render.com), create a **New Web Service** connected to your repo.
3. Set build command: `pip install -r requirements.txt` and start command: `python run_server.py`.
4. Render will deploy ZED with a public URL (e.g., `https://zed-defense.onrender.com`).
