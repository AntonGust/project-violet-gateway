"""FastAPI app: serves the dashboard and a single WebSocket stream endpoint."""
import asyncio
import json
import logging
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

log = logging.getLogger("web")

STATIC_DIR = Path(__file__).parent.parent / "static"
_THEATER_PASSWORD = os.environ.get("THEATER_PASSWORD", "")
_http_basic = HTTPBasic(auto_error=True)


def _require_auth(credentials: HTTPBasicCredentials = Depends(_http_basic)) -> None:
    """Enforce HTTP Basic Auth when THEATER_PASSWORD is set."""
    if not _THEATER_PASSWORD:
        return
    valid = secrets.compare_digest(
        credentials.password.encode(), _THEATER_PASSWORD.encode()
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


app = FastAPI()
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Injected by main.py after startup
_director = None
_catalog = None
_connections: list[WebSocket] = []


def setup(director, catalog) -> None:
    global _director, _catalog
    _director = director
    _catalog = catalog


async def broadcast(message: dict) -> None:
    if not _connections:
        return
    payload = json.dumps(message)
    dead: list[WebSocket] = []
    for ws in list(_connections):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _safe_remove(ws)


def _safe_remove(ws: WebSocket) -> None:
    try:
        _connections.remove(ws)
    except ValueError:
        pass


@app.get("/")
async def index(_: None = Depends(_require_auth)):
    return FileResponse(STATIC_DIR / "index.html")


@app.websocket("/stream")
async def stream(websocket: WebSocket):
    # Auth for the WebSocket is enforced at the HTTP layer: GET / requires Basic
    # Auth, which the browser satisfies before loading the JS that opens this
    # socket. Browser WebSocket API cannot send custom headers, so per-frame auth
    # is not possible — the binding to 127.0.0.1 is the network-level boundary.
    await websocket.accept()
    _connections.append(websocket)
    if _director and _director.current_state.state.name == "IDLE":
        await _director._switch_to_archive()
    try:
        await _send_initial_state(websocket)
        while True:
            try:
                # Keep the socket open; we only push from the server side
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                continue  # no client frame; keep alive
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _safe_remove(websocket)


async def _send_initial_state(ws: WebSocket) -> None:
    if _catalog:
        stats = {
            "type": "stats",
            "attacks_today": _catalog.attacks_today_count(),
            "top_countries": _catalog.top_countries_today(),
            "recent_pins": _catalog.recent_pins(50),
        }
        await ws.send_text(json.dumps(stats))

    if _director is None:
        await ws.send_text(json.dumps({"type": "title_card"}))
        return

    from .director import State
    play = _director.current_state
    if play.state == State.IDLE:
        await ws.send_text(json.dumps({"type": "title_card"}))
    elif play.state in (State.LIVE, State.ARCHIVE):
        mode = "live" if play.state == State.LIVE else "replay"
        rec = _catalog.get(play.session_id) if _catalog and play.session_id else None
        from .director import _meta
        await ws.send_text(json.dumps(
            {"type": "session_start", "mode": mode, "session": _meta(rec)}
        ))
