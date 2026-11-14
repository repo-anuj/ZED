"""
ZED Collector API & Real-time WebSocket Daemon
FastAPI application serving REST endpoints, telemetry ingestion,
WebSocket live feeds, and the terminal-themed interface.
"""

import os
import json
import asyncio
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import psutil

from zed.config import SERVER_HOST, SERVER_PORT, BASE_DIR
from zed.models import TelemetryEvent, Alert, BehaviorFeatures
from zed.db import db
from zed.engine.dispatcher import dispatcher
from zed.engine.ml_engine import ml_engine
from zed.agent.response import response_executor
from zed.bot.attack_simulator import bot

app = FastAPI(title="ZED EDR Daemon", version="1.0.0")

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths for static and templates
STATIC_DIR = BASE_DIR / "zed" / "web" / "static"
TEMPLATES_DIR = BASE_DIR / "zed" / "web" / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

START_TIME = time.time()


# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dc in dead_connections:
            self.disconnect(dc)


ws_manager = ConnectionManager()
loop: Optional[asyncio.AbstractEventLoop] = None


# Hook Dispatcher into WebSocket Manager
def on_dispatcher_event(event_dict: Dict[str, Any]):
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast_json({"type": "EVENT", "data": event_dict}),
            loop
        )


def on_dispatcher_alert(alert_dict: Dict[str, Any]):
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast_json({"type": "ALERT", "data": alert_dict}),
            loop
        )


def on_dispatcher_metric(metric_dict: Dict[str, Any]):
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast_json(metric_dict),
            loop
        )


def on_bot_log(msg: str):
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast_json({"type": "BOT_LOG", "message": msg}),
            loop
        )


dispatcher.register_event_listener(on_dispatcher_event)
dispatcher.register_alert_listener(on_dispatcher_alert)
dispatcher.register_metric_listener(on_dispatcher_metric)
bot.log_callback = on_bot_log


@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()


# Web UI Route
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>ZED Terminal UI template not found</h1>", status_code=500)
    with open(index_file, "r") as f:
        return HTMLResponse(f.read())


# Demo Victim Website Route (For Non-Tech Observers & Teacher Presentations)
@app.get("/demo", response_class=HTMLResponse)
async def serve_demo():
    demo_file = TEMPLATES_DIR / "demo_portal.html"
    if not demo_file.exists():
        return HTMLResponse("<h1>ZED Demo Portal template not found</h1>", status_code=500)
    with open(demo_file, "r") as f:
        return HTMLResponse(f.read())


# REST Endpoints
@app.get("/api/v1/stats")
async def get_system_stats():
    uptime_sec = int(time.time() - START_TIME)
    threat_summary = db.get_threat_summary()

    # System telemetry
    mem = psutil.virtual_memory()
    cpu_pct = psutil.cpu_percent()

    return {
        "uptime_sec": uptime_sec,
        "uptime_formatted": f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m {uptime_sec % 60}s",
        "cpu_percent": cpu_pct,
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_percent": mem.percent,
        "threat_summary": threat_summary,
        "ml_status": {
            "trained": ml_engine.is_trained,
            "samples": ml_engine.baseline_stats.get("samples", 0),
            "contamination": ml_engine.baseline_stats.get("contamination", 0.04)
        },
        "auto_response": response_executor.auto_response_enabled
    }


@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50):
    return db.get_recent_alerts(limit)


@app.get("/api/v1/events")
async def get_events(limit: int = 50):
    return db.get_recent_events(limit)


@app.post("/api/v1/event")
async def ingest_event(payload: Dict[str, Any]):
    ev = TelemetryEvent(
        event_type=payload.get("event_type", "TELEMETRY"),
        process_name=payload.get("process_name", ""),
        pid=payload.get("pid"),
        ppid=payload.get("ppid"),
        cmdline=payload.get("cmdline", ""),
        dest_ip=payload.get("dest_ip", ""),
        dest_port=payload.get("dest_port"),
        file_path=payload.get("file_path", ""),
        file_action=payload.get("file_action", ""),
        details=payload.get("details", {})
    )
    dispatcher.handle_event(ev)
    return {"status": "INGESTED"}


@app.post("/api/v1/attack")
async def trigger_attack(payload: Dict[str, Any]):
    scenario_id = int(payload.get("scenario", 1))
    # Run in threadpool so it doesn't block async event loop
    res = await asyncio.to_thread(bot.run_scenario, scenario_id)
    return res


@app.post("/api/v1/train")
async def retrain_baseline():
    res = await asyncio.to_thread(ml_engine.train_baseline, 400)
    await ws_manager.broadcast_json({
        "type": "SYSTEM_NOTIFY",
        "message": f"[OK] ML Baseline retrained successfully ({res['samples']} samples, Isolation Forest fit)."
    })
    return res


@app.post("/api/v1/response/kill")
async def kill_process(payload: Dict[str, Any]):
    pid = payload.get("pid")
    if not pid:
        raise HTTPException(status_code=400, detail="PID required")
    res = response_executor.terminate_process(pid=int(pid), process_name=payload.get("process_name", ""))
    return res


@app.post("/api/v1/clear")
async def clear_database():
    db.clear_all()
    await ws_manager.broadcast_json({"type": "LOGS_CLEARED"})
    return {"status": "CLEARED"}


@app.get("/api/v1/export")
async def export_report():
    summary = db.get_threat_summary()
    alerts = db.get_recent_alerts(100)

    report = f"""# ZED (Zero-day Endpoint Detection & Response) - Evaluation Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
Host: Linux Mint 64-bit | RAM: 8GB Profile | Engine: Dual Engine (MITRE Rules + Isolation Forest)

## 1. Threat Summary
- Total Telemetry Events Processed: {summary['total_events']}
- Total Alerts Raised: {summary['total_alerts']}
- Rule-Engine Detections: {summary['rule_alerts']}
- Machine Learning Anomaly Detections: {summary['ml_alerts']}
- Automated Responses Executed: {summary['responses_executed']}

## 2. MITRE ATT&CK Technique Distribution
"""
    for tech, count in summary.get("mitre_distribution", {}).items():
        report += f"- **{tech}**: {count} detections\n"

    report += "\n## 3. Incident Log (Last 100 Alerts)\n| ID | Timestamp | Source | Severity | Technique | Rule / Description | Response |\n|---|---|---|---|---|---|---|\n"
    for a in alerts:
        report += f"| {a['id']} | {a['timestamp']} | {a['source']} | {a['severity']} | {a['technique_id']} | {a['rule_name']} | {a['response_action']} |\n"

    return PlainTextResponse(report, media_type="text/markdown")


# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial boot status
        await websocket.send_json({
            "type": "SYSTEM_NOTIFY",
            "message": "[OK] Connected to ZED Kernel-Telemetry Event Bus (WebSocket Active)"
        })

        while True:
            data = await websocket.receive_text()
            try:
                cmd_data = json.loads(data)
                cmd_type = cmd_data.get("action")

                if cmd_type == "ATTACK":
                    scenario = int(cmd_data.get("scenario", 1))
                    asyncio.create_task(asyncio.to_thread(bot.run_scenario, scenario))

                elif cmd_type == "TRAIN":
                    asyncio.create_task(asyncio.to_thread(ml_engine.train_baseline, 400))

                elif cmd_type == "CLEAR":
                    db.clear_all()
                    await ws_manager.broadcast_json({"type": "LOGS_CLEARED"})

                elif cmd_type == "TERMINATE":
                    pid = cmd_data.get("pid")
                    if pid:
                        res = response_executor.terminate_process(pid=int(pid))
                        await websocket.send_json({"type": "SYSTEM_NOTIFY", "message": res["message"]})

            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
