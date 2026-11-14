"""
ZED Agent Telemetry Monitor
Tracks processes, filesystem mutations, active network sockets, and auth events.
Aggregates telemetry into behavioral feature windows for the ML detection engine.
"""

import time
import threading
import os
from pathlib import Path
from typing import Dict, Set, List, Callable, Optional, Any
from datetime import datetime
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from zed.config import (
    SANDBOX_DIR,
    SANDBOX_CRON_DIR,
    ML_WINDOW_SECONDS
)
from zed.models import TelemetryEvent, EventType, BehaviorFeatures


class ZEDFileEventHandler(FileSystemEventHandler):
    """Watches sensitive and sandbox directories for file modifications."""
    def __init__(self, callback: Callable[[TelemetryEvent], None]):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if event.is_directory:
            return
        ev = TelemetryEvent(
            event_type=EventType.FILE_CHANGE,
            file_path=event.src_path,
            file_action="CREATE",
            details={"src": event.src_path}
        )
        self.callback(ev)

    def on_modified(self, event):
        if event.is_directory:
            return
        ev = TelemetryEvent(
            event_type=EventType.FILE_CHANGE,
            file_path=event.src_path,
            file_action="MODIFY",
            details={"src": event.src_path}
        )
        self.callback(ev)

    def on_moved(self, event):
        if event.is_directory:
            return
        ev = TelemetryEvent(
            event_type=EventType.FILE_CHANGE,
            file_path=event.dest_path,
            file_action="RENAME",
            details={"src": event.src_path, "dest": event.dest_path}
        )
        self.callback(ev)

    def on_deleted(self, event):
        if event.is_directory:
            return
        ev = TelemetryEvent(
            event_type=EventType.FILE_CHANGE,
            file_path=event.src_path,
            file_action="DELETE",
            details={"src": event.src_path}
        )
        self.callback(ev)


class AgentMonitor:
    def __init__(self, event_callback: Optional[Callable[[TelemetryEvent], None]] = None,
                 feature_callback: Optional[Callable[[BehaviorFeatures], None]] = None):
        self.event_callback = event_callback or (lambda e: None)
        self.feature_callback = feature_callback or (lambda f: None)
        self.running = False

        self._known_pids: Set[int] = set()
        self._known_connections: Set[str] = set()

        # Telemetry counters for rolling ML window
        self._window_new_procs: List[str] = []
        self._window_file_events = 0
        self._window_net_events = 0
        self._window_dest_ips: Set[str] = set()
        self._window_auth_fails = 0
        self._window_lock = threading.Lock()

        # Watchdog File Observer
        self._file_observer = Observer()

    def record_auth_failure(self, username: str = "root", source_ip: str = "127.0.0.1"):
        """Injected when brute force simulator or system auth detects failure."""
        with self._window_lock:
            self._window_auth_fails += 1

        ev = TelemetryEvent(
            event_type=EventType.AUTH_EVENT,
            details={"username": username, "source_ip": source_ip, "status": "FAIL"}
        )
        self.event_callback(ev)

    def record_custom_event(self, event: TelemetryEvent):
        """Allows direct injection of simulated telemetry from test harnesses."""
        with self._window_lock:
            if event.event_type == EventType.PROCESS_SPAWN:
                self._window_new_procs.append(event.process_name)
            elif event.event_type == EventType.FILE_CHANGE:
                self._window_file_events += 1
            elif event.event_type == EventType.NET_CONN:
                self._window_net_events += 1
                if event.dest_ip:
                    self._window_dest_ips.add(event.dest_ip)
            elif event.event_type == EventType.AUTH_EVENT:
                self._window_auth_fails += 1

        self.event_callback(event)

    def _init_process_baseline(self):
        """Snapshots currently active PIDs so existing OS processes are not marked new."""
        for p in psutil.process_iter(['pid']):
            try:
                self._known_pids.add(p.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _start_file_monitoring(self):
        handler = ZEDFileEventHandler(self._on_file_event)
        # Watch sandbox directories
        if SANDBOX_DIR.exists():
            self._file_observer.schedule(handler, str(SANDBOX_DIR), recursive=True)
        if SANDBOX_CRON_DIR.exists():
            self._file_observer.schedule(handler, str(SANDBOX_CRON_DIR), recursive=True)
        self._file_observer.start()

    def _on_file_event(self, event: TelemetryEvent):
        with self._window_lock:
            self._window_file_events += 1
        self.event_callback(event)

    def _poll_processes(self):
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                if pid not in self._known_pids:
                    # New Process Spawned!
                    p_name = proc.info['name'] or ""
                    ppid = proc.info['ppid']
                    cmdline = " ".join(proc.info['cmdline'] or [])

                    # Attempt to resolve parent name
                    parent_name = ""
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    ev = TelemetryEvent(
                        event_type=EventType.PROCESS_SPAWN,
                        process_name=p_name,
                        pid=pid,
                        ppid=ppid,
                        parent_name=parent_name,
                        cmdline=cmdline,
                        details={"parent_name": parent_name, "cmdline": cmdline}
                    )
                    with self._window_lock:
                        self._window_new_procs.append(p_name)
                    self.event_callback(ev)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._known_pids = current_pids

    def _poll_network(self):
        try:
            connections = psutil.net_connections(kind='inet')
            current_conns = set()
            for c in connections:
                if c.raddr:
                    dest_ip = c.raddr.ip
                    dest_port = c.raddr.port
                    conn_id = f"{c.pid}_{dest_ip}_{dest_port}"
                    current_conns.add(conn_id)

                    if conn_id not in self._known_connections:
                        p_name = ""
                        if c.pid:
                            try:
                                p_name = psutil.Process(c.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        ev = TelemetryEvent(
                            event_type=EventType.NET_CONN,
                            process_name=p_name,
                            pid=c.pid,
                            dest_ip=dest_ip,
                            dest_port=dest_port,
                            details={"status": c.status}
                        )
                        with self._window_lock:
                            self._window_net_events += 1
                            self._window_dest_ips.add(dest_ip)
                        self.event_callback(ev)
            self._known_connections = current_conns
        except (psutil.AccessDenied, PermissionError):
            pass

    def _window_aggregation_loop(self):
        """Periodically extracts feature vector and dispatches to ML Anomaly engine."""
        last_cpu_times = psutil.cpu_percent()
        while self.running:
            time.sleep(ML_WINDOW_SECONDS)
            current_cpu = psutil.cpu_percent()
            cpu_entropy = abs(current_cpu - last_cpu_times)
            last_cpu_times = current_cpu

            with self._window_lock:
                new_proc_count = len(self._window_new_procs)
                unique_binaries = len(set(self._window_new_procs))
                file_mods = self._window_file_events
                net_conns = self._window_net_events
                dest_ips = len(self._window_dest_ips)
                auth_fails = self._window_auth_fails

                # Reset window counters
                self._window_new_procs = []
                self._window_file_events = 0
                self._window_net_events = 0
                self._window_dest_ips = set()
                self._window_auth_fails = 0

            features = BehaviorFeatures(
                new_proc_rate=round(new_proc_count / ML_WINDOW_SECONDS, 2),
                unique_binaries=unique_binaries,
                file_mod_rate=round(file_mods / ML_WINDOW_SECONDS, 2),
                net_conn_rate=round(net_conns / ML_WINDOW_SECONDS, 2),
                distinct_dest_ips=dest_ips,
                auth_fail_rate=round(auth_fails / ML_WINDOW_SECONDS, 2),
                cpu_entropy=round(cpu_entropy, 2)
            )
            self.feature_callback(features)

    def start(self):
        """Starts monitoring background threads."""
        self.running = True
        self._init_process_baseline()
        self._start_file_monitoring()

        # Process & Network poll loop
        def poll_loop():
            while self.running:
                self._poll_processes()
                self._poll_network()
                time.sleep(0.5)

        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()

        self._agg_thread = threading.Thread(target=self._window_aggregation_loop, daemon=True)
        self._agg_thread.start()

    def stop(self):
        self.running = False
        if self._file_observer.is_alive():
            self._file_observer.stop()
            self._file_observer.join(timeout=1.0)
