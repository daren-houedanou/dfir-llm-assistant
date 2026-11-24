"""High-level analyst workflows: summarize, ask, generate hunting queries.

Every LLM answer goes through validation:
* reports must be valid JSON with the expected keys (one automatic repair round);
* ATT&CK IDs are checked against the local catalog;
* IOCs are checked against the raw events (grounding), so invented values are flagged;
* generated queries are syntax-checked (Sigma YAML, jq compile) and jq filters can be
  executed against the loaded evtx_dump JSONL to report hit counts.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import context as ctx
from . import parsers, prompts
from .detect import attack, rules
from .llm import Completion, LLMClient, extract_code, extract_json
from .models import Event, Finding
from .privacy import Pseudonymizer

REPORT_KEYS = {"summary", "verdict", "techniques", "iocs", "next_steps"}


@dataclass
class Report:
    data: dict
    completion: Completion
    unknown_techniques: list[str] = field(default_factory=list)
    ungrounded_iocs: list[str] = field(default_factory=list)
    repaired: bool = False

    @property
    def technique_ids(self) -> set[str]:
        return {
            t.get("id", "") for t in self.data.get("techniques", []) if isinstance(t, dict)
        } | attack.extract_ids(
            " ".join(str(t) for t in self.data.get("techniques", []) if isinstance(t, str))
        )


@dataclass
class QueryResult:
    target: str
    query: str
    explanation: str
    valid: bool
    error: str | None
    completion: Completion
    hits: int | None = None


class Investigation:
    def __init__(
        self,
        events: list[Event],
        client: LLMClient | None = None,
        *,
        allow_cloud: bool = False,
        model: str | None = None,
        budget_tokens: int = 6000,
    ):
        self.events = events
        self.findings: list[Finding] = rules.run_all(events)
        self.client = client or LLMClient()
        self.allow_cloud = allow_cloud
        self.model = model
        self.budget_tokens = budget_tokens
        self.history: list[dict[str, str]] = []
        self.pseudonymizer = Pseudonymizer()
        for e in events:
            self.pseudonymizer.register_event(e)
        self._context: ctx.Context | None = None
        self._haystack: str | None = None

    @classmethod
    def from_paths(cls, paths: list[Path], fmt: str | None = None, **kwargs) -> Investigation:
        inv = cls(parsers.load(paths, fmt), **kwargs)
        if inv.client.audit is not None:
            inv.client.audit.set_inputs(paths)  # SHA-256 of every artifact, recorded with each model call
        return inv

    @property
    def context(self) -> ctx.Context:
        if self._context is None:
            self._context = ctx.build(self.events, self.findings, self.budget_tokens)
        return self._context

    def _complete(
        self,
        prompt: str,
        json_mode: bool = False,
        history: list[dict[str, str]] | None = None,
        operation: str = "complete",
    ) -> Completion:
        return self.client.complete(
            prompts.SYSTEM,
            prompt,
            model=self.model,
            allow_cloud=self.allow_cloud,
            json_mode=json_mode,
            pseudonymizer=self.pseudonymizer,
            history=history,
            operation=operation,
        )

    # ------------------------------------------------------------------ grounding

    def _grounded(self, value: str) -> bool:
        if self._haystack is None:
            parts = []
            for e in self.events:
                parts.append(
                    " ".join(str(v) for v in (e.host, e.user, e.src_ip, e.dst_ip, e.process, e.message))
                )
                parts.append(" ".join(str(v) for v in e.fields.values()))
            self._haystack = "\n".join(parts).lower()
        return value.lower() in self._haystack

    # ------------------------------------------------------------------ workflows

    def summarize(self) -> Report:
        prompt = prompts.SUMMARIZE.format(context=self.context.text)
        completion = self._complete(prompt, json_mode=True, operation="summarize")
        repaired = False
        try:
            data = extract_json(completion.text)
            missing = REPORT_KEYS - data.keys()
            if missing:
                raise ValueError(f"missing keys: {sorted(missing)}")
        except ValueError as exc:
            repaired = True
            history = [{"role": "user", "content": prompt}, {"role": "assistant", "content": completion.text}]
            completion = self._complete(
                prompts.REPAIR.format(error=exc),
                json_mode=True,
                history=history,
                operation="summarize-repair",
            )
            data = extract_json(completion.text)
        report = Report(data=data, completion=completion, repaired=repaired)
        report.unknown_techniques = sorted(t for t in report.technique_ids if t and not attack.is_known(t))
        for ioc in data.get("iocs", []):
            value = str(ioc.get("value", "")) if isinstance(ioc, dict) else str(ioc)
            if value and not self._grounded(value):
                report.ungrounded_iocs.append(value)
        return report

    def ask(self, question: str) -> Completion:
        prompt = prompts.ASK.format(question=question, context=self.context.text)
        completion = self._complete(prompt, history=self.history[-6:], operation="ask")
        self.history += [
            {"role": "user", "content": f"Question: {question}"},
            {"role": "assistant", "content": completion.text},
        ]
        return completion

    def generate_query(self, need: str, target: str, test_files: list[Path] | None = None) -> QueryResult:
        return generate_query(
            self.client, need, target, model=self.model, allow_cloud=self.allow_cloud, test_files=test_files
        )


def validate_query(target: str, query: str) -> str | None:
    """Return an error message, or None when the query is syntactically valid."""
    if not query.strip():
        return "empty query"
    if target == "sigma":
        try:
            rule = yaml.safe_load(query)
        except yaml.YAMLError as exc:
            return f"invalid YAML: {exc}"
        if not isinstance(rule, dict):
            return "Sigma rule must be a YAML mapping"
        missing = [k for k in ("title", "logsource", "detection") if k not in rule]
        if missing:
            return f"Sigma rule missing keys: {missing}"
        if "condition" not in (rule.get("detection") or {}):
            return "Sigma detection has no condition"
    elif target == "jq" and shutil.which("jq"):
        proc = subprocess.run(
            ["jq", "-n", f"def __f: {query}; empty"], capture_output=True, text=True, timeout=10
        )
        if proc.returncode != 0:
            return f"jq compile error: {proc.stderr.strip()[:300]}"
    elif target in {"spl", "kql", "eql"}:
        if query.count("(") != query.count(")") or query.count('"') % 2:
            return "unbalanced parentheses or quotes"
    return None


def run_jq(query: str, files: list[Path]) -> int:
    hits = 0
    for path in files:
        proc = subprocess.run(["jq", "-c", query, str(path)], capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            hits += sum(1 for line in proc.stdout.splitlines() if line.strip() not in ("", "null", "false"))
    return hits


def generate_query(
    client: LLMClient,
    need: str,
    target: str,
    *,
    model: str | None = None,
    allow_cloud: bool = False,
    test_files: list[Path] | None = None,
) -> QueryResult:
    if target not in prompts.QUERY_TARGETS:
        raise ValueError(f"unknown target {target!r}; choose from {', '.join(prompts.QUERY_TARGETS)}")
    name, hint = prompts.QUERY_TARGETS[target]
    prompt = prompts.QUERY.format(target_name=name, need=need, schema_hint=hint)
    completion = client.complete(
        prompts.SYSTEM, prompt, model=model, allow_cloud=allow_cloud, operation=f"query-{target}"
    )
    query = extract_code(completion.text)
    error = validate_query(target, query)
    if error:  # one repair round with the validator's message
        history = [{"role": "user", "content": prompt}, {"role": "assistant", "content": completion.text}]
        completion = client.complete(
            prompts.SYSTEM,
            prompts.REPAIR.format(error=error),
            model=model,
            allow_cloud=allow_cloud,
            history=history,
            operation=f"query-{target}-repair",
        )
        query = extract_code(completion.text)
        error = validate_query(target, query)
    explanation = completion.text.rsplit("```", 1)[-1].strip()
    hits = None
    if target == "jq" and not error and test_files and shutil.which("jq"):
        hits = run_jq(query, test_files)
    return QueryResult(
        target=target,
        query=query,
        explanation=explanation,
        valid=error is None,
        error=error,
        completion=completion,
        hits=hits,
    )
