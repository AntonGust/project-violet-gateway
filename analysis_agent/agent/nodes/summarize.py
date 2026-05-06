"""Summarize node: generate a concise analyst-friendly report via LLM."""
import dataclasses
import logging
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger("nodes.summarize")

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=False)

_LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://172.20.10.2:8080/v1")
_LLM_API_KEY  = os.environ.get("LLM_API_KEY",  "proxy-no-key-needed")
_LLM_MODEL    = os.environ.get("LLM_MODEL",     "gpt-4.1-mini")

_SYSTEM = (
    "You are a senior threat intelligence analyst reviewing honeypot SSH sessions. "
    "Write concise, factual reports in markdown. Focus on attacker intent, "
    "observed TTPs, and defensive recommendations. Avoid speculation."
)


async def summarize_node(state):
    if state.done or state.error:
        return state

    try:
        prompt = _jinja.get_template("summarize.jinja2").render(
            session_id=state.session_id,
            src_ip=state.src_ip,
            country=state.country,
            asn_org=state.asn_org,
            hop=state.hop,
            duration=state.duration,
            command_count=state.command_count,
            commands=state.commands,
            attack_type=state.attack_type,
            severity=state.severity,
            ttps=state.ttps,
            threat_context=state.threat_context,
        )
        summary = await _call_llm(prompt)
        log.info("Summarized session %s", state.session_id)
        return dataclasses.replace(state, summary=summary.strip())
    except Exception as exc:
        log.exception("summarize_node failed for %s", state.session_id)
        return dataclasses.replace(state, error=str(exc))


async def _call_llm(prompt: str) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(base_url=_LLM_BASE_URL, api_key=_LLM_API_KEY)
    resp = await client.chat.completions.create(
        model=_LLM_MODEL,
        max_tokens=2048,
        messages=[
            {"role": "system", "content": _SYSTEM},
            {"role": "user",   "content": prompt},
        ],
    )
    return resp.choices[0].message.content or ""
