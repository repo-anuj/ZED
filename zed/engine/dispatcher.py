"""
ZED Central Dispatcher
Connects telemetry, dual detection engines (Rules + ML), SQLite threat store,
automated response executor, and live WebSocket broadcasts.
"""

import asyncio
from typing import Callable, List, Optional, Dict, Any
from zed.models import TelemetryEvent, Alert, BehaviorFeatures
from zed.db import db
from zed.engine.rule_engine import BehavioralRuleEngine
from zed.engine.ml_engine import ml_engine
from zed.agent.response import response_executor


class ThreatDispatcher:
    def __init__(self):
        self.rule_engine = BehavioralRuleEngine()
        self.ml_engine = ml_engine
        self.response_executor = response_executor

        # Broadcast callbacks (e.g. WebSocket manager)
        self._event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._alert_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._metric_listeners: List[Callable[[Dict[str, Any]], None]] = []

    def register_event_listener(self, callback: Callable[[Dict[str, Any]], None]):
        self._event_listeners.append(callback)

    def register_alert_listener(self, callback: Callable[[Dict[str, Any]], None]):
        self._alert_listeners.append(callback)

    def register_metric_listener(self, callback: Callable[[Dict[str, Any]], None]):
        self._metric_listeners.append(callback)

    def handle_event(self, event: TelemetryEvent):
        """Processes an incoming raw telemetry event from the agent."""
        # 1. Persist in database
        event_id = db.insert_event(event)

        # Broadcast raw event to listeners (WebSocket / console)
        event_dict = event.to_dict()
        event_dict["id"] = event_id
        for listener in self._event_listeners:
            try:
                listener(event_dict)
            except Exception:
                pass

        # 2. Evaluate with Rule Engine
        alert = self.rule_engine.evaluate_event(event)
        if alert:
            self._process_alert(alert)

    def handle_features(self, features: BehaviorFeatures):
        """Processes a rolling feature window with the ML Anomaly Detection engine."""
        alert, raw_score, deviations = self.ml_engine.score_features(features)

        # Broadcast metrics update
        metric_payload = {
            "type": "METRIC_UPDATE",
            "score": round(raw_score, 4),
            "is_anomaly": (alert is not None),
            "features": features.to_array(),
            "deviations": deviations,
            "timestamp": features.timestamp
        }
        for listener in self._metric_listeners:
            try:
                listener(metric_payload)
            except Exception:
                pass

        if alert:
            self._process_alert(alert)

    def _process_alert(self, alert: Alert):
        """Handles alert persistence, automated response execution, and notifications."""
        # 1. Execute Automated Response if suggested
        if alert.response_action == "TERMINATE_PROCESS" and alert.pid:
            result = self.response_executor.terminate_process(
                pid=alert.pid,
                process_name=alert.process_name
            )
            alert.details += f" | Response: {result['message']}"
            alert.response_action = result["status"]
        elif alert.response_action == "BLOCK_IP" and "details" in alert.to_dict():
            # If target IP extracted from details or alert
            pass

        # 2. Persist alert in SQLite
        alert_id = db.insert_alert(alert)
        alert_dict = alert.to_dict()
        alert_dict["id"] = alert_id

        # 3. Broadcast alert to live UI
        for listener in self._alert_listeners:
            try:
                listener(alert_dict)
            except Exception:
                pass


# Global Dispatcher instance
dispatcher = ThreatDispatcher()
