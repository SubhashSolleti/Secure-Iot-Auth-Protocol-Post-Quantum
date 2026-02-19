"""
Web Backend for IoT Auth Protocol Dashboard.

Provides:
- REST API to start/stop Server and Client processes.
- WebSocket endpoint to stream combined structured logs to the frontend.
- Static file serving for the dashboard UI.
"""

import asyncio
import json
import os
import signal
import sys
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Ensure root dir is in path for subprocesses
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global State ─────────────────────────────────────────────────────────
class ProcessManager:
    def __init__(self):
        self.server_proc: Optional[asyncio.subprocess.Process] = None
        self.client_proc: Optional[asyncio.subprocess.Process] = None
        self.active_websockets: List[WebSocket] = []

    async def broadcast(self, message: dict):
        """Send a JSON message to all connected clients."""
        to_remove = []
        for ws in self.active_websockets:
            try:
                await ws.send_json(message)
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            self.active_websockets.remove(ws)

    async def stream_output(self, process, source: str):
        """Read stdout from a subprocess and broadcast lines as logs."""
        if not process.stdout:
            return
        
        # process.stdout is already a StreamReader
        
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode().strip()
            if not text:
                continue
            
            # Try to parse as JSON (structlog), else wrap as text
            try:
                data = json.loads(text)
                # Ensure structlog fields are preserved
            except json.JSONDecodeError:
                data = {
                    "event": "raw_output",
                    "message": text,
                    "level": "info",
                    "logger": source,
                    "timestamp": None
                }
            
            # Tag with source if not present
            if "logger" not in data:
                data["logger"] = source
                
            await self.broadcast(data)

    async def start_server(self):
        if self.server_proc and self.server_proc.returncode is None:
            return {"status": "already_running"}

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        
        self.server_proc = await asyncio.create_subprocess_exec(
            sys.executable, "server.py",
            cwd=ROOT_DIR,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.create_task(self.stream_output(self.server_proc, "server"))
        return {"status": "started", "pid": self.server_proc.pid}

    async def stop_server(self):
        if self.server_proc and self.server_proc.returncode is None:
            self.server_proc.terminate()
            try:
                await asyncio.wait_for(self.server_proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self.server_proc.kill()
        return {"status": "stopped"}

    async def start_client(self):
        # Client runs once then exits, so we allow re-running freely
        if self.client_proc and self.client_proc.returncode is None:
            return {"status": "already_running"}

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        self.client_proc = await asyncio.create_subprocess_exec(
            sys.executable, "client.py",
            cwd=ROOT_DIR,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.create_task(self.stream_output(self.client_proc, "client"))
        return {"status": "started", "pid": self.client_proc.pid}

    async def rotate_epoch(self):
        # Trigger explicit rotation commands if needed, 
        # but for now we rely on the implementation's auto-rotation.
        # We could also modify secrets_config.py or delete device_state.json
        pass


mgr = ProcessManager()


# ── API Endpoints ────────────────────────────────────────────────────────

@app.post("/api/server/start")
async def start_server():
    return await mgr.start_server()

@app.post("/api/server/stop")
async def stop_server():
    return await mgr.stop_server()

@app.post("/api/client/start")
async def start_client():
    return await mgr.start_client()

@app.post("/api/reset_state")
async def reset_state():
    # Helper to clear persistent state for a fresh demo
    state_file = os.path.join(ROOT_DIR, "device_state.json")
    if os.path.exists(state_file):
        os.remove(state_file)
    
    # Also clear pinned key
    pinned_key = os.path.join(ROOT_DIR, "pinned_server.pk")
    if os.path.exists(pinned_key):
        os.remove(pinned_key)
        
    return {"status": "reset_complete"}

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    mgr.active_websockets.append(websocket)
    try:
        while True:
            # Keep connection alive, maybe handle incoming control messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        mgr.active_websockets.remove(websocket)


# ── Static Files (Frontend) ──────────────────────────────────────────────
app.mount("/", StaticFiles(directory=os.path.join(ROOT_DIR, "web/static"), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
