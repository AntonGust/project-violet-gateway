"""Integration test: spin up the app against fixture data and verify WebSocket messages."""
import asyncio
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from app.catalog import Catalog
from app.director import Director
from app import web

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
async def running_app(tmp_path: Path):
    """Start catalog + director + web app wired together."""
    catalog = Catalog(tmp_path / "integration.db")
    await catalog.init()
    director = Director(catalog, web.broadcast)
    web.setup(director, catalog)
    await director.run()
    yield web.app
    await catalog.close()
    web.setup(None, None)


class TestWebEndpoints:
    async def test_index_returns_html(self, running_app):
        async with AsyncClient(transport=ASGITransport(app=running_app), base_url="http://test") as client:
            r = await client.get("/")
            assert r.status_code == 200
            assert "text/html" in r.headers["content-type"]

    async def test_static_css_served(self, running_app):
        async with AsyncClient(transport=ASGITransport(app=running_app), base_url="http://test") as client:
            r = await client.get("/static/style.css")
            assert r.status_code == 200

    async def test_static_js_served(self, running_app):
        async with AsyncClient(transport=ASGITransport(app=running_app), base_url="http://test") as client:
            r = await client.get("/static/app.js")
            assert r.status_code == 200


class TestWebSocketStream:
    async def test_connect_receives_initial_state(self, running_app):
        from starlette.testclient import TestClient
        client = TestClient(running_app)
        with client.websocket_connect("/stream") as ws:
            # Should receive at least one initial message (stats or title_card)
            data = ws.receive_text()
            msg = json.loads(data)
            assert "type" in msg
            assert msg["type"] in ("stats", "title_card", "session_start")

    async def test_second_connect_receives_initial_state(self, running_app):
        # Two independent clients should each get an initial state message
        from starlette.testclient import TestClient
        client = TestClient(running_app)
        with client.websocket_connect("/stream") as ws1:
            msg1 = json.loads(ws1.receive_text())
            assert "type" in msg1
        with client.websocket_connect("/stream") as ws2:
            msg2 = json.loads(ws2.receive_text())
            assert "type" in msg2
