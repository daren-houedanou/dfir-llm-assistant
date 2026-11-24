"""Normalized data model shared by parsers, detectors and the LLM layer.

Every artifact (EVTX record, syslog line, timeline row, Zeek connection...) is
converted into an :class:`Event`. Keeping one flat schema is what makes
cross-artifact correlation and compact LLM context possible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    timestamp: datetime | None
    source: str  # parser family: evtx, linux, timeline, zeek, memory
    event_type: str  # e.g. "Security/4625", "sshd/failed_password", "zeek/conn"
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    process: str | None = None
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    artifact: str = ""  # file the event came from
    ref: int = 0  # position in the artifact, used as evidence pointer

    def to_line(self, max_len: int = 220) -> str:
        """One-line, token-cheap rendering used in LLM prompts."""
        ts = self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if self.timestamp else "?"
        parts = [ts, self.host or "-", self.event_type]
        kv = []
        for key in ("user", "src_ip", "dst_ip", "dst_port", "process"):
            value = getattr(self, key)
            if value not in (None, ""):
                kv.append(f"{key}={value}")
        if self.message:
            kv.append(self.message)
        line = " | ".join(parts) + (" | " + " ".join(kv) if kv else "")
        return line if len(line) <= max_len else line[: max_len - 1] + "…"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


@dataclass(slots=True)
class Finding:
    """Output of a deterministic detection rule (pre-LLM triage)."""

    rule: str
    title: str
    severity: str  # low | medium | high | critical
    techniques: list[str]
    description: str
    evidence: list[Event] = field(default_factory=list)
    indicators: dict[str, list[str]] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.evidence if e.timestamp]
        return min(stamps) if stamps else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "techniques": self.techniques,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "evidence_count": len(self.evidence),
            "indicators": self.indicators,
        }


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
