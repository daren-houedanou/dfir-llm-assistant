"""Evaluation harness.

A scenario is a YAML file pointing at artifacts plus ground truth (verdict, ATT&CK
techniques, IOCs, Q&A pairs). For every scenario and every model alias, the harness
runs the full pipeline (parse -> rules -> context -> LLM -> validation) and scores:

* verdict accuracy, exact and lenient ("danger seen": suspicious counts on a real attack);
* ATT&CK precision / recall / F1, exact and at parent-technique level;
* IOC recall (expected indicators found in the report);
* hallucination signals: ungrounded IOCs, unknown technique IDs;
* Q&A accuracy (expected keywords in the answer);
* latency and token usage;
* privacy: raw sensitive values found in prompts sent to non-local models (must be 0).

The ``rules`` pseudo-model (deterministic findings echoed by the mock backend) is
always included as a baseline, so the LLM's added value is measurable.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..assistant import Investigation
from ..audit import AuditLog
from ..llm import LLMClient, MockBackend, Settings


@dataclass
class Scenario:
    name: str
    description: str
    artifacts: list[Path]
    verdict: str
    techniques: set[str]
    iocs: list[str]
    questions: list[dict]

    @classmethod
    def load(cls, path: Path) -> Scenario:
        raw = yaml.safe_load(path.read_text())
        exp = raw.get("expected", {})
        return cls(
            name=raw["name"],
            description=raw.get("description", ""),
            artifacts=[(path.parent / a).resolve() for a in raw["artifacts"]],
            verdict=exp.get("verdict", "malicious"),
            techniques=set(exp.get("techniques", [])),
            iocs=[str(i) for i in exp.get("iocs", [])],
            questions=raw.get("questions", []),
        )


@dataclass
class RunResult:
    scenario: str
    model: str
    verdict_ok: bool
    tech_precision: float
    tech_recall: float
    parent_recall: float
    ioc_recall: float
    qa_accuracy: float | None
    ungrounded: int
    unknown_techniques: int
    leaks: int
    latency_s: float
    tokens: int
    error: str | None = None
    verdict_given: str = ""
    danger_seen: bool = False
    missed_techniques: list[str] = field(default_factory=list)

    @property
    def tech_f1(self) -> float:
        p, r = self.tech_precision, self.tech_recall
        return 2 * p * r / (p + r) if p + r else 0.0


def _parent(t: str) -> str:
    return t.split(".")[0]


def score_techniques(predicted: set[str], expected: set[str]) -> tuple[float, float, float]:
    predicted = {t for t in predicted if t}
    if not predicted and not expected:
        return 1.0, 1.0, 1.0
    if not predicted:
        return 0.0, 0.0, 0.0
    precision = len(predicted & expected) / len(predicted)
    recall = len(predicted & expected) / len(expected) if expected else 1.0
    exp_parents = {_parent(t) for t in expected}
    parent_recall = (
        len({_parent(t) for t in predicted} & exp_parents) / len(exp_parents) if exp_parents else 1.0
    )
    return precision, recall, parent_recall


DANGER = {"malicious", "suspicious"}


def verdict_scores(given: str, expected: str) -> tuple[bool, bool]:
    """Exact match, and a lenient score: was the danger (or its absence) seen?

    A cautious "suspicious" on a real attack is a correct triage, just under-confident, so it
    counts for ``danger_seen`` but not for the exact verdict.
    """
    exact = given == expected
    if expected in DANGER:
        return exact, given in DANGER
    return exact, exact


def run_one(scenario: Scenario, model: str, allow_cloud: bool, audit: AuditLog | None = None) -> RunResult:
    if model == "rules":
        client = LLMClient(Settings(backend="mock", local_models={"rules"}), backend=MockBackend())
    else:
        client = LLMClient(audit=audit)  # every model call of an evaluation is in the audit trail too
    inv = Investigation.from_paths(scenario.artifacts, client=client, model=model, allow_cloud=allow_cloud)
    try:
        report = inv.summarize()
    except Exception as exc:  # noqa: BLE001 - a failed run is a data point, not a crash
        return RunResult(scenario.name, model, False, 0, 0, 0, 0, None, 0, 0, 0, 0.0, 0, error=str(exc)[:200])

    predicted = report.technique_ids
    precision, recall, parent_recall = score_techniques(predicted, scenario.techniques)
    haystack = (str(report.data.get("iocs", "")) + " " + str(report.data.get("summary", ""))).lower()
    ioc_hits = sum(1 for i in scenario.iocs if i.lower() in haystack)
    verdict = str(report.data.get("verdict", "")).lower().strip()
    verdict_ok, danger_seen = verdict_scores(verdict, scenario.verdict)

    completions = [report.completion]
    qa_scores = []
    for qa in scenario.questions:
        answer = inv.ask(qa["q"])
        completions.append(answer)
        expected_any = [str(x).lower() for x in qa.get("expect_any", [])]
        qa_scores.append(any(x in answer.text.lower() for x in expected_any))

    leaks = 0
    for c in completions:
        if c.pseudonymized:
            leaks += len(inv.pseudonymizer.leaked(c.sent_prompt))
    return RunResult(
        scenario=scenario.name,
        model=model,
        verdict_ok=verdict_ok,
        verdict_given=verdict,
        danger_seen=danger_seen,
        tech_precision=precision,
        tech_recall=recall,
        parent_recall=parent_recall,
        ioc_recall=ioc_hits / len(scenario.iocs) if scenario.iocs else 1.0,
        qa_accuracy=sum(qa_scores) / len(qa_scores) if qa_scores else None,
        ungrounded=len(report.ungrounded_iocs),
        unknown_techniques=len(report.unknown_techniques),
        leaks=leaks,
        latency_s=sum(c.latency_s for c in completions),
        tokens=sum(c.prompt_tokens + c.completion_tokens for c in completions),
        missed_techniques=sorted(scenario.techniques - predicted),
    )


def run_suite(
    scenarios_dir: Path,
    models: list[str],
    allow_cloud: bool = False,
    repeat: int = 1,
    console=None,
    audit: AuditLog | None = None,
) -> list[RunResult]:
    files = sorted(scenarios_dir.glob("*.yaml")) if scenarios_dir.is_dir() else [scenarios_dir]
    scenarios = [Scenario.load(f) for f in files]
    results = []
    for scenario in scenarios:
        for model in ["rules", *models]:
            for _ in range(repeat if model != "rules" else 1):
                if console:
                    console.print(f"[dim]running {scenario.name} with {model}...[/dim]")
                results.append(run_one(scenario, model, allow_cloud, audit))
    return results


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.0f}%"


def render_markdown(results: list[RunResult]) -> str:
    lines = [
        "# Evaluation report",
        "",
        "| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if r.error:
            lines.append(f"| {r.scenario} | {r.model} | error: {r.error} ||||||||||||")
            continue
        lines.append(
            f"| {r.scenario} | {r.model} | {'✅' if r.verdict_ok else '❌'} {r.verdict_given} | {'✅' if r.danger_seen else '❌'} | {_pct(r.tech_precision)} | {_pct(r.tech_recall)} "
            f"| {_pct(r.parent_recall)} | {r.tech_f1:.2f} | {_pct(r.ioc_recall)} | {_pct(r.qa_accuracy)} | {r.ungrounded} "
            f"| {r.leaks} | {r.latency_s:.1f}s | {r.tokens} |"
        )
    lines += [
        "",
        "## Aggregate per model",
        "",
        "| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for model in dict.fromkeys(r.model for r in results):
        rs = [r for r in results if r.model == model and not r.error]
        if not rs:
            lines.append(f"| {model} | 0 | all runs failed ||||||")
            continue
        qa = [r.qa_accuracy for r in rs if r.qa_accuracy is not None]
        lines.append(
            f"| {model} | {len(rs)} | {_pct(sum(r.verdict_ok for r in rs) / len(rs))} | "
            f"{_pct(sum(r.danger_seen for r in rs) / len(rs))} | "
            f"{statistics.mean(r.tech_f1 for r in rs):.2f} | {_pct(statistics.mean(r.ioc_recall for r in rs))} | "
            f"{_pct(statistics.mean(qa)) if qa else 'n/a'} | {sum(r.leaks for r in rs)} | "
            f"{statistics.median(r.latency_s for r in rs):.1f}s |"
        )
    missed = [(r.scenario, r.model, r.missed_techniques) for r in results if r.missed_techniques]
    if missed:
        lines += ["", "## Missed techniques", ""] + [f"- {s} / {m}: {', '.join(t)}" for s, m, t in missed]
    return "\n".join(lines) + "\n"
