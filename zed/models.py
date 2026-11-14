"""
ZED Data Models
Defines event types, alert schemas, feature vectors, and telemetry payloads.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List
from datetime import datetime
import json


class EventType:
    PROCESS_SPAWN = "PROCESS_SPAWN"
    FILE_CHANGE = "FILE_CHANGE"
    NET_CONN = "NET_CONN"
    AUTH_EVENT = "AUTH_EVENT"
    TELEMETRY_SAMPLE = "TELEMETRY_SAMPLE"


class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class TelemetryEvent:
    event_type: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    process_name: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_name: str = ""
    cmdline: str = ""
    dest_ip: str = ""
    dest_port: Optional[int] = None
    file_path: str = ""
    file_action: str = ""   # CREATE, MODIFY, DELETE, RENAME
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source: str = "RULE"               # "RULE" or "ML_ANOMALY"
    severity: str = Severity.MEDIUM
    technique_id: str = "T1059"        # MITRE ATT&CK ID
    rule_name: str = ""
    process_name: str = ""
    pid: Optional[int] = None
    details: str = ""
    anomaly_score: Optional[float] = None
    response_action: str = "LOGGED"    # "LOGGED", "KILLED", "BLOCKED", "IGNORED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BehaviorFeatures:
    """
    Numeric feature vector evaluated by Isolation Forest ML model.
    Captures behavioral velocity over rolling time windows.
    """
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    new_proc_rate: float = 0.0          # Process creations per second
    unique_binaries: int = 0            # Number of distinct executables seen
    file_mod_rate: float = 0.0          # File creations/modifications per second
    net_conn_rate: float = 0.0          # Network socket connections per second
    distinct_dest_ips: int = 0          # Number of distinct destination IP addresses
    auth_fail_rate: float = 0.0         # Failed login count in window
    cpu_entropy: float = 0.0            # CPU usage variation (%)

    def to_array(self) -> List[float]:
        return [
            float(self.new_proc_rate),
            float(self.unique_binaries),
            float(self.file_mod_rate),
            float(self.net_conn_rate),
            float(self.distinct_dest_ips),
            float(self.auth_fail_rate),
            float(self.cpu_entropy),
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "new_proc_rate",
            "unique_binaries",
            "file_mod_rate",
            "net_conn_rate",
            "distinct_dest_ips",
            "auth_fail_rate",
            "cpu_entropy",
        ]
