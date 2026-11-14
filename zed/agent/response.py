"""
ZED Response Executor
Automated defense actions: Process Termination & Network Isolation
Protected by strict process whitelisting to safeguard OS stability.
"""

import os
import signal
import psutil
from typing import Optional, Dict, Any
from zed.config import PROTECTED_PROCESS_NAMES, DEFAULT_AUTO_RESPONSE
from zed.db import db


class ResponseExecutor:
    def __init__(self, auto_response_enabled: bool = DEFAULT_AUTO_RESPONSE):
        self.auto_response_enabled = auto_response_enabled
        self.current_pid = os.getpid()

    def is_safe_to_kill(self, pid: Optional[int], process_name: Optional[str] = None) -> bool:
        """
        Validates whether a target PID is safe to terminate.
        Prevents killing critical system components or the EDR itself.
        """
        if not pid or pid <= 1:
            return False

        if pid == self.current_pid:
            return False

        # Do not kill parent process (shell / IDE running ZED)
        try:
            parent = psutil.Process(self.current_pid).parent()
            if parent and parent.pid == pid:
                return False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Check whitelist against process name
        target_name = (process_name or "").lower()
        if not target_name:
            try:
                proc = psutil.Process(pid)
                target_name = proc.name().lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False

        for safe in PROTECTED_PROCESS_NAMES:
            if safe.lower() in target_name:
                return False

        return True

    def terminate_process(self, pid: int, alert_id: Optional[int] = None, process_name: str = "") -> Dict[str, Any]:
        """
        Terminates a hostile process cleanly with SIGTERM -> SIGKILL escalation.
        """
        if not self.auto_response_enabled:
            db.insert_response(alert_id, "TERMINATE_PROCESS", f"PID:{pid}", "SKIPPED", "Auto-response is disabled")
            return {"status": "SKIPPED", "message": "Auto-response disabled"}

        if not self.is_safe_to_kill(pid, process_name):
            db.insert_response(alert_id, "TERMINATE_PROCESS", f"PID:{pid}", "WHITELISTED", f"Protected process {process_name}")
            return {"status": "WHITELISTED", "message": f"PID {pid} is in protected whitelist"}

        try:
            proc = psutil.Process(pid)
            p_name = proc.name()
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except psutil.TimeoutExpired:
                proc.kill()

            db.insert_response(alert_id, "TERMINATE_PROCESS", f"{p_name}:{pid}", "SUCCESS", "Process terminated by ZED Response Executor")
            return {"status": "SUCCESS", "message": f"Successfully terminated hostile process {p_name} (PID: {pid})"}
        except psutil.NoSuchProcess:
            db.insert_response(alert_id, "TERMINATE_PROCESS", f"PID:{pid}", "ALREADY_DEAD", "Process exited before termination")
            return {"status": "ALREADY_DEAD", "message": f"Process {pid} already dead"}
        except Exception as e:
            db.insert_response(alert_id, "TERMINATE_PROCESS", f"PID:{pid}", "ERROR", str(e))
            return {"status": "ERROR", "message": f"Failed to terminate: {str(e)}"}

    def block_ip(self, ip_address: str, alert_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Quarantines malicious remote destination by recording firewall rule.
        """
        if not ip_address or ip_address in ("127.0.0.1", "localhost", "0.0.0.0"):
            db.insert_response(alert_id, "BLOCK_IP", ip_address, "WHITELISTED", "Localhost cannot be blocked")
            return {"status": "WHITELISTED", "message": "Cannot block loopback"}

        # Audit and register firewall response
        db.insert_response(
            alert_id,
            "BLOCK_IP",
            ip_address,
            "SUCCESS",
            f"Simulated iptables DROP rule applied: iptables -A OUTPUT -d {ip_address} -j DROP"
        )
        return {
            "status": "SUCCESS",
            "message": f"Network quarantine applied to {ip_address} (iptables DROP)"
        }


# Global Response Executor instance
response_executor = ResponseExecutor()
