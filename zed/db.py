"""
ZED SQLite Threat Store
Persistent storage for raw telemetry events, detection alerts, response logs, and ML baselines.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from zed.config import DB_PATH
from zed.models import Alert, TelemetryEvent


class ThreatStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for smooth asynchronous reads & writes
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Telemetry Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                process_name TEXT,
                pid INTEGER,
                ppid INTEGER,
                cmdline TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                file_path TEXT,
                file_action TEXT,
                details TEXT
            );
            """)

            # Alerts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,          -- 'RULE' or 'ML_ANOMALY'
                severity TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                process_name TEXT,
                pid INTEGER,
                details TEXT,
                anomaly_score REAL,
                response_action TEXT DEFAULT 'LOGGED'
            );
            """)

            # Automated Responses Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_id INTEGER,
                action_type TEXT NOT NULL,     -- 'TERMINATE_PROCESS', 'BLOCK_IP'
                target TEXT NOT NULL,
                status TEXT NOT NULL,          -- 'SUCCESS', 'FAILED', 'WHITELISTED'
                details TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );
            """)

            # ML Baseline Metadata Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trained_at TEXT NOT NULL,
                sample_count INTEGER,
                contamination REAL,
                status TEXT
            );
            """)
            conn.commit()

    def insert_event(self, event: TelemetryEvent) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO events (
                timestamp, event_type, process_name, pid, ppid,
                cmdline, dest_ip, dest_port, file_path, file_action, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.event_type,
                event.process_name,
                event.pid,
                event.ppid,
                event.cmdline,
                event.dest_ip,
                event.dest_port,
                event.file_path,
                event.file_action,
                json.dumps(event.details) if event.details else "{}"
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_alert(self, alert: Alert) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO alerts (
                timestamp, source, severity, technique_id, rule_name,
                process_name, pid, details, anomaly_score, response_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp,
                alert.source,
                alert.severity,
                alert.technique_id,
                alert.rule_name,
                alert.process_name,
                alert.pid,
                alert.details,
                alert.anomaly_score,
                alert.response_action
            ))
            conn.commit()
            alert.id = cursor.lastrowid
            return cursor.lastrowid

    def insert_response(self, alert_id: Optional[int], action_type: str, target: str, status: str, details: str = "") -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO responses (timestamp, alert_id, action_type, target, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), alert_id, action_type, target, status, details))
            conn.commit()
            return cursor.lastrowid

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_threat_summary(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE source = 'RULE'")
            rule_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE source = 'ML_ANOMALY'")
            ml_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM responses WHERE status = 'SUCCESS'")
            responses_executed = cursor.fetchone()[0]

            # MITRE breakdown
            cursor.execute("SELECT technique_id, COUNT(*) as count FROM alerts GROUP BY technique_id ORDER BY count DESC")
            mitre_counts = {row["technique_id"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "rule_alerts": rule_alerts,
                "ml_alerts": ml_alerts,
                "responses_executed": responses_executed,
                "mitre_distribution": mitre_counts
            }

    def clear_all(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM responses")
            cursor.execute("DELETE FROM sqlite_sequence")
            conn.commit()


# Global Singleton Store
db = ThreatStore()
