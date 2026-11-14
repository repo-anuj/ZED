"""
ZED Behavioral Rule Engine
Maps system activity directly to MITRE ATT&CK techniques.
Detects known post-exploitation behaviors without relying on static file signatures.
"""

import time
from collections import defaultdict, deque
from typing import Optional, List, Dict
from zed.models import TelemetryEvent, EventType, Alert, Severity
from zed.config import (
    RANSOMWARE_TRIGGER_COUNT,
    RANSOMWARE_WINDOW_SEC,
    BRUTE_FORCE_TRIGGER_COUNT,
    BRUTE_FORCE_WINDOW_SEC,
    BEACON_MIN_COUNT,
    BEACON_INTERVAL_TOLERANCE
)


class BehavioralRuleEngine:
    def __init__(self):
        # State tracking for sliding windows
        self._file_burst_tracker = deque()               # (timestamp, file_path)
        self._auth_fail_tracker = deque()                # (timestamp, username, ip)
        self._beacon_tracker = defaultdict(list)         # (dest_ip, dest_port) -> [timestamps]

        # Web server process names
        self.web_servers = {
            "nginx", "apache2", "httpd", "lighttpd", "tomcat",
            "uvicorn", "gunicorn", "caddy", "node", "fake_web_server"
        }
        # Interactive shells
        self.shells = {
            "bash", "sh", "dash", "zsh", "csh", "ksh", "ash"
        }

    def evaluate_event(self, event: TelemetryEvent) -> Optional[Alert]:
        """
        Runs all MITRE ATT&CK behavioral detection rules against the event.
        Returns an Alert if a rule is triggered, or None.
        """
        now = time.time()

        # Rule 1: MITRE T1059.004 - Suspicious Process Chain (Web Server -> Shell)
        if event.event_type == EventType.PROCESS_SPAWN:
            alert = self._check_web_shell(event)
            if alert:
                return alert

        # Rule 2: MITRE T1053.003 - Persistence via Cron Modification
        if event.event_type == EventType.FILE_CHANGE:
            alert = self._check_cron_persistence(event)
            if alert:
                return alert

        # Rule 3: MITRE T1486 - Ransomware File Encryption Burst
        if event.event_type == EventType.FILE_CHANGE:
            alert = self._check_ransomware_burst(event, now)
            if alert:
                return alert

        # Rule 4: MITRE T1071.001 - Outbound C2 Beaconing
        if event.event_type == EventType.NET_CONN:
            alert = self._check_beaconing(event, now)
            if alert:
                return alert

        # Rule 5: MITRE T1110.001 - Password Brute Force
        if event.event_type == EventType.AUTH_EVENT:
            alert = self._check_brute_force(event, now)
            if alert:
                return alert

        return None

    def _check_web_shell(self, event: TelemetryEvent) -> Optional[Alert]:
        p_name = (event.process_name or "").lower()
        parent_name = (event.parent_name or "").lower()
        cmdline = (event.cmdline or "").lower()

        # Check if parent is a web server and spawned process is a shell
        is_web_parent = any(web in parent_name for web in self.web_servers) or "http.server" in cmdline
        is_shell_child = any(sh == p_name or p_name.endswith(f"/{sh}") for sh in self.shells)

        # Also detect if cmdline contains explicit web server spawning interactive shell
        if is_web_parent and is_shell_child:
            return Alert(
                source="RULE",
                severity=Severity.CRITICAL,
                technique_id="T1059.004",
                rule_name="Web Server Spawned Interactive Shell",
                process_name=event.process_name,
                pid=event.pid,
                details=f"Web service '{event.parent_name}' spawned shell '{event.process_name}' (PID: {event.pid}). Classic web-shell / RCE signature.",
                response_action="TERMINATE_PROCESS"
            )

        # Detect simulated tag or command injection pattern
        if "web_shell_exploit" in cmdline:
            return Alert(
                source="RULE",
                severity=Severity.CRITICAL,
                technique_id="T1059.004",
                rule_name="Web Shell Reconnaissance Activity",
                process_name=event.process_name,
                pid=event.pid,
                details=f"Hostile web shell payload detected in execution context: {event.cmdline}",
                response_action="TERMINATE_PROCESS"
            )

        return None

    def _check_cron_persistence(self, event: TelemetryEvent) -> Optional[Alert]:
        path = (event.file_path or "").lower()
        # Watch standard cron paths and the sandbox cron directory
        if any(cron_dir in path for cron_dir in ["/etc/cron", "/var/spool/cron", "sandbox_cron"]):
            if event.file_action in ("CREATE", "MODIFY", "RENAME"):
                return Alert(
                    source="RULE",
                    severity=Severity.HIGH,
                    technique_id="T1053.003",
                    rule_name="Rogue Scheduled Task (Cron Persistence)",
                    process_name=event.process_name or "cron-writer",
                    pid=event.pid,
                    details=f"Persistence target written: '{event.file_path}' (Action: {event.file_action}). Unauthorized scheduled execution artifact.",
                    response_action="LOGGED"
                )
        return None

    def _check_ransomware_burst(self, event: TelemetryEvent, now: float) -> Optional[Alert]:
        # Track creations/renames
        if event.file_action in ("CREATE", "RENAME", "MODIFY"):
            path = event.file_path.lower()
            is_ransom_ext = any(path.endswith(ext) for ext in [".locked", ".crypto", ".enc", ".zed_ransom"])
            self._file_burst_tracker.append((now, path, is_ransom_ext))

        # Evict events outside rolling window
        while self._file_burst_tracker and (now - self._file_burst_tracker[0][0]) > RANSOMWARE_WINDOW_SEC:
            self._file_burst_tracker.popleft()

        total_in_window = len(self._file_burst_tracker)
        ransom_ext_count = sum(1 for _, _, is_ext in self._file_burst_tracker if is_ext)

        # Trigger if high volume or ransomware extension rapidly encountered
        if total_in_window >= RANSOMWARE_TRIGGER_COUNT or ransom_ext_count >= 4:
            self._file_burst_tracker.clear()
            return Alert(
                source="RULE",
                severity=Severity.CRITICAL,
                technique_id="T1486",
                rule_name="Mass File Encryption (Ransomware Velocity)",
                process_name=event.process_name or "ransom_sim",
                pid=event.pid,
                details=f"Mass file burst detected: {total_in_window} files encrypted/modified within {RANSOMWARE_WINDOW_SEC}s (Target: {event.file_path})",
                response_action="TERMINATE_PROCESS"
            )
        return None

    def _check_beaconing(self, event: TelemetryEvent, now: float) -> Optional[Alert]:
        dest_ip = event.dest_ip
        dest_port = event.dest_port
        if not dest_ip or dest_ip in ("127.0.0.1", "localhost", "0.0.0.0"):
            return None

        key = (dest_ip, dest_port)
        history = self._beacon_tracker[key]
        history.append(now)

        # Keep last 10 connection timestamps
        if len(history) > 10:
            history.pop(0)

        if len(history) >= BEACON_MIN_COUNT:
            # Calculate intervals between successive connections
            intervals = [history[i] - history[i-1] for i in range(1, len(history))]
            avg_interval = sum(intervals) / len(intervals)
            # Measure jitter (max deviation from average)
            jitter = max(abs(iv - avg_interval) for iv in intervals)

            if avg_interval > 0.3 and jitter <= BEACON_INTERVAL_TOLERANCE:
                self._beacon_tracker.pop(key, None)
                return Alert(
                    source="RULE",
                    severity=Severity.HIGH,
                    technique_id="T1071.001",
                    rule_name="Command & Control (C2) Beaconing Pattern",
                    process_name=event.process_name or "c2_client",
                    pid=event.pid,
                    details=f"Rhythmic beaconing detected to {dest_ip}:{dest_port} (Interval: {avg_interval:.2f}s, Jitter: {jitter:.2f}s)",
                    response_action="BLOCK_IP"
                )
        return None

    def _check_brute_force(self, event: TelemetryEvent, now: float) -> Optional[Alert]:
        if event.details.get("status") == "FAIL":
            username = event.details.get("username", "unknown")
            ip = event.details.get("source_ip", "local")
            self._auth_fail_tracker.append((now, username, ip))

        while self._auth_fail_tracker and (now - self._auth_fail_tracker[0][0]) > BRUTE_FORCE_WINDOW_SEC:
            self._auth_fail_tracker.popleft()

        if len(self._auth_fail_tracker) >= BRUTE_FORCE_TRIGGER_COUNT:
            count = len(self._auth_fail_tracker)
            self._auth_fail_tracker.clear()
            return Alert(
                source="RULE",
                severity=Severity.MEDIUM,
                technique_id="T1110.001",
                rule_name="Authentication Brute Force Velocity",
                process_name="sshd/pam",
                pid=event.pid,
                details=f"High-frequency authentication failures: {count} failed attempts in {BRUTE_FORCE_WINDOW_SEC}s",
                response_action="LOGGED"
            )
        return None
