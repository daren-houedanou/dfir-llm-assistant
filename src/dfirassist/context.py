"""Turn thousands of events into a compact, evidence-anchored prompt context.

Strategy (token budget aware):
1. global statistics (time range, hosts, sources, top event types, top IPs/users);
2. deterministic findings with their evidence lines;
3. a timeline of *notable* events: everything referenced by a finding, plus rare event
   types, plus a uniform sample of the rest, until the budget is spent.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .detect import attack
from .models import Event, Finding

CHARS_PER_TOKEN = 4  # conservative heuristic, good enough for budgeting


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN + 1


@dataclass
class Context:
    text: str
    events_total: int
    events_included: int
    findings: list[Finding]

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.text)


def _stats(events: list[Event]) -> str:
    stamps = [e.timestamp for e in events if e.timestamp]
    lines = [f"events: {len(events)}"]
    if stamps:
        lines.append(f"time range: {min(stamps):%Y-%m-%d %H:%M:%S}Z -> {max(stamps):%Y-%m-%d %H:%M:%S}Z")
    for label, values in (
        ("sources", [e.source for e in events]),
        ("hosts", [e.host for e in events if e.host]),
        ("event types", [e.event_type for e in events]),
        ("users", [e.user for e in events if e.user]),
        ("source IPs", [e.src_ip for e in events if e.src_ip]),
        ("destination IPs", [e.dst_ip for e in events if e.dst_ip]),
    ):
        common = Counter(values).most_common(8)
        if common:
            lines.append(f"{label}: " + ", ".join(f"{v} ({n})" for v, n in common))
    return "\n".join(lines)


def _findings_block(findings: list[Finding], evidence_per_finding: int = 3) -> str:
    if not findings:
        return "(no deterministic finding)"
    out = []
    for i, f in enumerate(findings, 1):
        techs = ", ".join(f"{t} {attack.name(t)}" for t in f.techniques)
        out.append(f"[F{i}] {f.severity.upper()} {f.title} | {techs}\n    {f.description}")
        if f.indicators:
            out.append(
                "    indicators: " + "; ".join(f"{k}={','.join(v)}" for k, v in f.indicators.items() if v)
            )
        for e in f.evidence[:evidence_per_finding]:
            out.append(f"    evidence: {e.to_line(180)}")
    return "\n".join(out)


def build(events: list[Event], findings: list[Finding], budget_tokens: int = 6000) -> Context:
    stats = "## Statistics\n" + _stats(events) + "\n\n## Deterministic findings\n"
    # Findings get at most ~60% of the budget: shrink evidence first, then drop the least severe findings
    # (they are sorted by severity) and say so, so the model knows the list is partial.
    cap = int(budget_tokens * CHARS_PER_TOKEN * 0.6)
    header = stats + _findings_block(findings)
    for per in (2, 1, 0):
        if len(header) <= cap:
            break
        header = stats + _findings_block(findings, per)
    kept = len(findings)
    while len(header) > cap and kept > 1:
        kept -= 1
        header = (
            stats
            + _findings_block(findings[:kept], 0)
            + f"\n({len(findings) - kept} lower-severity finding(s) omitted)"
        )
    remaining = budget_tokens * CHARS_PER_TOKEN - len(header) - 200

    evidence_ids = {id(e) for f in findings for e in f.evidence}
    type_counts = Counter(e.event_type for e in events)
    rare = {t for t, n in type_counts.items() if n <= 3}
    priority = [e for e in events if id(e) in evidence_ids or e.event_type in rare]
    others = [e for e in events if id(e) not in evidence_ids and e.event_type not in rare]

    chosen: list[Event] = []
    used = 0
    for e in priority:
        line_len = len(e.to_line()) + 1
        if used + line_len > remaining:
            break
        chosen.append(e)
        used += line_len
    if others and used < remaining:
        avg = sum(len(e.to_line()) for e in others[:200]) / min(len(others), 200) + 1
        slots = int((remaining - used) // avg)
        if slots > 0:
            step = max(1, len(others) // slots)
            for e in others[::step][:slots]:
                chosen.append(e)
    chosen.sort(key=lambda e: (e.timestamp is None, e.timestamp or 0))
    omitted = len(events) - len(chosen)
    timeline = "\n".join(e.to_line() for e in chosen)
    text = f"{header}\n\n## Timeline of notable events ({len(chosen)} shown, {omitted} omitted)\n{timeline}"
    return Context(text=text, events_total=len(events), events_included=len(chosen), findings=findings)
