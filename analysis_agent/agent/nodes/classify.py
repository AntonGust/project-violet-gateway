"""Classify node: use an LLM to identify attack type and TTPs."""
import dataclasses
import logging
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger("nodes.classify")

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=False)

_LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://172.20.10.2:8080/v1")
_LLM_API_KEY  = os.environ.get("LLM_API_KEY",  "proxy-no-key-needed")
_LLM_MODEL    = os.environ.get("LLM_MODEL",     "gpt-4.1-mini")


async def classify_node(state):
    if state.done or state.error:
        return state

    try:
        prompt = _jinja.get_template("classify.jinja2").render(
            src_ip=state.src_ip,
            country=state.country,
            asn_org=state.asn_org,
            hop=state.hop,
            duration=state.duration,
            command_count=state.command_count,
            commands=state.commands,
        )
        result = await _call_llm(prompt)
        attack_type, severity, ttps = _parse_classify(result)
        log.info("Session %s → %s (severity=%s)", state.session_id, attack_type, severity)
        return dataclasses.replace(state, attack_type=attack_type, severity=severity, ttps=ttps)
    except Exception as exc:
        log.exception("classify_node failed for %s", state.session_id)
        return dataclasses.replace(state, error=str(exc))


async def _call_llm(prompt: str) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(base_url=_LLM_BASE_URL, api_key=_LLM_API_KEY)
    resp = await client.chat.completions.create(
        model=_LLM_MODEL,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def _parse_classify(text: str) -> tuple[str, str, list[str]]:
    """Parse structured LLM output. Falls back to defaults on malformed response."""
    attack_type = "unknown"
    severity = "medium"
    ttps: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("attack_type:"):
            attack_type = line.split(":", 1)[1].strip().lower()
        elif line.lower().startswith("severity:"):
            severity = line.split(":", 1)[1].strip().lower()
        elif line.lower().startswith("ttps:"):
            raw = line.split(":", 1)[1].strip()
            ttps = [t.strip() for t in raw.split(",") if t.strip()]

    return attack_type, severity, ttps
