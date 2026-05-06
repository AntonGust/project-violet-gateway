"""LangGraph state for the session analysis pipeline."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionAnalysisState:
    # Input — set by ingest node
    session_id: str = ""
    src_ip: str = ""
    country: str = ""
    asn_org: str = ""
    hop: int = 0
    duration: float = 0.0
    command_count: int = 0
    commands: list[str] = field(default_factory=list)
    tty_file_path: Optional[str] = None

    # Intermediate — set by classify / enrich nodes
    attack_type: str = ""
    severity: str = ""
    ttps: list[str] = field(default_factory=list)
    threat_context: str = ""

    # Output — set by summarize node
    summary: str = ""

    # Control
    error: Optional[str] = None
    done: bool = False
