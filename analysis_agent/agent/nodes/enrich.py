"""Enrich node: add threat intelligence context via LLM."""
import dataclasses
import logging
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

log = logging.getLogger("nodes.enrich")

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=False)

_LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://172.20.10.2:8080/v1")
_LLM_API_KEY  = os.environ.get("LLM_API_KEY",  "proxy-no-key-needed")
_LLM_MODEL    = os.environ.get("LLM_MODEL",     "gpt-4.1-mini")


async def enrich_node(state):
    if state.done or state.error:
        return state

    try:
        prompt = _jinja.get_template("enrich.jinja2").render(
            src_ip=state.src_ip,
            country=state.country,
            asn_org=state.asn_org,
            attack_type=state.attack_type,
            severity=state.severity,
            ttps=state.ttps,
            commands=state.commands,
        )
        result = await _call_llm(prompt)
        log.info("Enriched session %s", state.session_id)
        return dataclasses.replace(state, threat_context=result.strip())
    except Exception as exc:
        log.exception("enrich_node failed for %s", state.session_id)
        return dataclasses.replace(state, error=str(exc))


async def _call_llm(prompt: str) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(base_url=_LLM_BASE_URL, api_key=_LLM_API_KEY)
    resp = await client.chat.completions.create(
        model=_LLM_MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""
