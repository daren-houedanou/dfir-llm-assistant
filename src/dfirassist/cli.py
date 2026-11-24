"""``dfa``: command line interface for analysts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from . import __version__, parsers
from .assistant import Investigation, generate_query
from .audit import AuditLog
from .detect import attack
from .llm import GatewayError, LLMClient, PolicyError, Settings

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="LLM-assisted DFIR triage for nix-forensics artifacts (evtx_dump, auth.log, bodyfile, Plaso, Zeek).",
)
console = Console()
err = Console(stderr=True)

Files = Annotated[list[Path], typer.Argument(exists=True, help="Artifact files or directories")]
Fmt = Annotated[str | None, typer.Option("--format", "-f", help="Force parser: evtx, linux, timeline, zeek")]
Cloud = Annotated[bool, typer.Option("--cloud", help="Allow a cloud model (prompt is pseudonymized first)")]
Model = Annotated[
    str | None, typer.Option("--model", "-m", help="LiteLLM model alias (default: DFA_LOCAL_MODEL)")
]
Budget = Annotated[int, typer.Option("--budget", help="Context budget in tokens")]

DISCLAIMER = (
    "LLM-generated analytic aid, not evidence: verify each statement against the deterministic "
    "findings [F#] and the original artifacts before reporting it."
)

# Audit trail settings, set by the global callback below.
STATE: dict = {"audit": None}


@app.callback()
def main_options(
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", envvar="DFA_AUDIT_LOG", help="JSONL audit trail of every model call"),
    ] = Path("dfa-audit.jsonl"),
    no_audit: Annotated[bool, typer.Option("--no-audit", help="Do not record model calls")] = False,
    case_id: Annotated[str, typer.Option("--case", envvar="DFA_CASE_ID", help="Case identifier")] = "",
) -> None:
    STATE["audit"] = None if no_audit else AuditLog(audit_log, case_id=case_id)


def _client() -> LLMClient:
    return LLMClient(audit=STATE["audit"])


SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "dim"}


def _investigation(
    files: list[Path], fmt: str | None, cloud: bool, model: str | None, budget: int
) -> Investigation:
    try:
        return Investigation.from_paths(
            files, fmt, client=_client(), allow_cloud=cloud, model=model, budget_tokens=budget
        )
    except parsers.UnknownFormatError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc


def _guard(fn):
    try:
        return fn()
    except PolicyError as exc:
        err.print(Panel(str(exc), title="blocked by confidentiality policy", border_style="red"))
        raise typer.Exit(3) from exc
    except GatewayError as exc:
        err.print(f"[red]{exc}[/red]\nStart the gateway (deploy/docker-compose.yml) or use DFA_BACKEND=mock.")
        raise typer.Exit(4) from exc


def _footer(completion, inv: Investigation | None = None) -> None:
    bits = [f"model={completion.model}", f"latency={completion.latency_s:.1f}s"]
    if completion.prompt_tokens:
        bits.append(f"tokens={completion.prompt_tokens}+{completion.completion_tokens}")
    if inv:
        bits.append(
            f"context={inv.context.events_included}/{inv.context.events_total} events (~{inv.context.tokens} tok)"
        )
    bits.append("pseudonymized" if completion.pseudonymized else "local-only")
    console.print("[dim]" + " · ".join(bits) + "[/dim]")


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"dfir-llm-assistant {__version__}")


@app.command()
def parse(
    files: Files,
    fmt: Fmt = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write normalized JSONL")] = None,
    limit: Annotated[int, typer.Option(help="Rows to display")] = 30,
) -> None:
    """Parse artifacts into the normalized event schema."""
    events = parsers.load(files, fmt)
    if output:
        with output.open("w") as handle:
            for e in events:
                handle.write(json.dumps(e.to_dict(), default=str) + "\n")
        console.print(f"wrote {len(events)} events to {output}")
        return
    table = Table(title=f"{len(events)} events", show_lines=False)
    for col in ("time", "host", "type", "user", "src", "message"):
        table.add_column(col, overflow="fold")
    for e in events[:limit]:
        table.add_row(
            f"{e.timestamp:%Y-%m-%d %H:%M:%S}" if e.timestamp else "?",
            e.host or "",
            e.event_type,
            e.user or "",
            e.src_ip or "",
            e.message[:80],
        )
    console.print(table)


@app.command()
def triage(
    files: Files,
    fmt: Fmt = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output")] = False,
) -> None:
    """Run deterministic detections only (offline, no LLM)."""
    events = parsers.load(files, fmt)
    from .detect import rules

    findings = rules.run_all(events)
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    if not findings:
        console.print(f"[green]No finding on {len(events)} events.[/green]")
        return
    table = Table(title=f"{len(findings)} finding(s) on {len(events)} events")
    for col in ("sev", "first seen", "finding", "ATT&CK", "details"):
        table.add_column(col, overflow="fold")
    for f in findings:
        table.add_row(
            f"[{SEV_STYLE[f.severity]}]{f.severity}[/]",
            f"{f.first_seen:%m-%d %H:%M:%S}" if f.first_seen else "",
            f.title,
            "\n".join(f"{t} {attack.name(t)}" for t in f.techniques),
            f.description[:160],
        )
    console.print(table)


@app.command()
def summarize(
    files: Files,
    fmt: Fmt = None,
    cloud: Cloud = False,
    model: Model = None,
    budget: Budget = 6000,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    show_prompt: Annotated[bool, typer.Option(help="Print exactly what was sent to the model")] = False,
) -> None:
    """Produce an LLM incident report (summary, timeline, ATT&CK, IOCs, next steps)."""
    inv = _investigation(files, fmt, cloud, model, budget)
    with console.status("analysing..."):
        report = _guard(inv.summarize)
    if as_json:
        print(json.dumps(report.data, indent=2, ensure_ascii=False))
        return
    d = report.data
    md = [
        f"## Verdict: {d.get('verdict', '?')} (confidence {d.get('confidence', '?')})",
        "",
        d.get("summary", ""),
    ]
    if d.get("timeline"):
        md += ["", "### Timeline"] + [
            f"- `{t.get('time', '')}` **{t.get('host', '')}** {t.get('event', '')}"
            for t in d["timeline"]
            if isinstance(t, dict)
        ]
    if d.get("techniques"):
        md += ["", "### MITRE ATT&CK"] + [
            f"- **{t.get('id')}** {t.get('name', '')}: {t.get('evidence', '')}"
            for t in d["techniques"]
            if isinstance(t, dict)
        ]
    if d.get("iocs"):
        md += ["", "### IOCs"] + [
            f"- {i.get('type')}: `{i.get('value')}`" for i in d["iocs"] if isinstance(i, dict)
        ]
    if d.get("next_steps"):
        md += ["", "### Next steps"] + [f"- {s}" for s in d["next_steps"]]
    console.print(Markdown("\n".join(md)))
    console.print(f"[italic dim]{DISCLAIMER}[/italic dim]")
    if report.unknown_techniques:
        console.print(
            f"[yellow]⚠ unknown ATT&CK IDs (possible hallucination): {report.unknown_techniques}[/yellow]"
        )
    if report.ungrounded_iocs:
        console.print(f"[yellow]⚠ IOCs not found in the artifacts: {report.ungrounded_iocs}[/yellow]")
    if show_prompt:
        console.print(Panel(report.completion.sent_prompt, title="prompt sent"))
    _footer(report.completion, inv)


@app.command()
def ask(
    files: Files,
    question: Annotated[str, typer.Option("--question", "-q", prompt=True)],
    fmt: Fmt = None,
    cloud: Cloud = False,
    model: Model = None,
    budget: Budget = 6000,
) -> None:
    """Ask a free-form question about the artifacts."""
    inv = _investigation(files, fmt, cloud, model, budget)
    with console.status("thinking..."):
        completion = _guard(lambda: inv.ask(question))
    console.print(Markdown(completion.text))
    _footer(completion, inv)


@app.command()
def query(
    need: Annotated[str, typer.Argument(help="What to hunt for, in plain language")],
    target: Annotated[str, typer.Option("--target", "-t", help="spl, kql, eql, sigma, jq, zeek")] = "sigma",
    test: Annotated[
        list[Path] | None, typer.Option("--test", help="evtx_dump JSONL files to run a jq query on")
    ] = None,
    cloud: Cloud = False,
    model: Model = None,
) -> None:
    """Generate (and validate) a hunting query on the fly."""
    client = _client()
    result = _guard(
        lambda: generate_query(client, need, target, model=model, allow_cloud=cloud, test_files=test)
    )
    lexer = {"sigma": "yaml", "jq": "bash", "zeek": "bash"}.get(target, "sql")
    console.print(Markdown(f"```{lexer}\n{result.query}\n```"))
    if result.explanation:
        console.print(result.explanation)
    status = "[green]valid[/green]" if result.valid else f"[red]invalid: {result.error}[/red]"
    console.print(
        f"syntax check: {status}"
        + (f" · {result.hits} hit(s) on test data" if result.hits is not None else "")
    )
    _footer(result.completion)
    if not result.valid:
        raise typer.Exit(1)


@app.command()
def tui(
    files: Files, fmt: Fmt = None, cloud: Cloud = False, model: Model = None, budget: Budget = 6000
) -> None:
    """Interactive terminal UI (requires the 'tui' extra)."""
    try:
        from .tui import run
    except ImportError as exc:
        err.print("Textual is not installed: pip install 'dfir-llm-assistant[tui]'")
        raise typer.Exit(1) from exc
    run(_investigation(files, fmt, cloud, model, budget))


@app.command()
def models() -> None:
    """List model aliases exposed by the LiteLLM gateway and their policy class."""
    settings = Settings()
    client = LLMClient(settings)
    if settings.backend == "mock":
        console.print("mock backend (offline)")
        return
    try:
        names = client.backend.models()
    except Exception as exc:  # noqa: BLE001
        err.print(f"[red]gateway unreachable at {settings.gateway_url}: {exc}[/red]")
        raise typer.Exit(4) from exc
    table = Table(title=f"gateway {settings.gateway_url}")
    table.add_column("alias")
    table.add_column("policy")
    for n in names:
        table.add_row(
            n,
            "[green]local[/green]"
            if n in settings.local_models
            else "[yellow]cloud (pseudonymized)[/yellow]",
        )
    console.print(table)


@app.command("eval")
def evaluate(
    scenarios: Annotated[Path, typer.Argument(exists=True)] = Path("eval/scenarios"),
    models_: Annotated[
        list[str] | None, typer.Option("--model", "-m", help="Model alias(es) to compare")
    ] = None,
    cloud: Cloud = False,
    report: Annotated[Path | None, typer.Option("--report", "-r", help="Write a Markdown report")] = None,
    repeat: Annotated[int, typer.Option(help="Runs per scenario (variance)")] = 1,
) -> None:
    """Benchmark the pipeline on labelled scenarios (rules baseline vs LLMs)."""
    from .eval.harness import render_markdown, run_suite

    results = run_suite(
        scenarios, models_ or [], allow_cloud=cloud, repeat=repeat, console=console, audit=STATE["audit"]
    )
    md = render_markdown(results)
    console.print(Markdown(md))
    if report:
        report.write_text(md)
        console.print(f"report written to {report}")


audit_app = typer.Typer(no_args_is_help=True, help="Inspect, verify and replay the audit trail.")
app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify(
    log: Annotated[Path, typer.Argument(exists=True)] = Path("dfa-audit.jsonl"),
    skip_inputs: Annotated[bool, typer.Option("--skip-inputs", help="Do not re-hash artifacts")] = False,
) -> None:
    """Check the hash chain and that artifacts still match their recorded SHA-256."""
    from . import audit

    result = audit.verify(log, check_inputs=not skip_inputs)
    console.print(f"{result.records} record(s)")
    if result.chain_ok:
        console.print("[green]hash chain intact[/green]")
    else:
        console.print(
            f"[red]hash chain broken at record {result.broken_at}: log was edited or truncated[/red]"
        )
    for m in result.input_mismatches:
        console.print(f"[red]input {m}[/red]")
    if not result.chain_ok or result.input_mismatches:
        raise typer.Exit(1)


@audit_app.command("show")
def audit_show(log: Annotated[Path, typer.Argument(exists=True)] = Path("dfa-audit.jsonl")) -> None:
    """Summarize the recorded model calls."""
    from . import audit

    table = Table()
    for col in ("#", "time", "operation", "model (served)", "params", "inputs", "response sha256"):
        table.add_column(col, overflow="fold")
    for i, rec in enumerate(audit.read(log)):
        p = rec["params"]
        table.add_row(
            str(i),
            rec["timestamp"][:19],
            rec["operation"],
            f"{rec['model_alias']} ({rec['served_model']})",
            f"T={p.get('temperature')} seed={p.get('seed')}",
            str(len(rec.get("inputs", []))),
            rec["response_sha256"][:16],
        )
    console.print(table)


@audit_app.command("replay")
def audit_replay(
    log: Annotated[Path, typer.Argument(exists=True)] = Path("dfa-audit.jsonl"),
    record: Annotated[int | None, typer.Option("--record", "-n", help="Replay one record only")] = None,
) -> None:
    """Re-send recorded requests unchanged and check whether the answers are byte-identical."""
    from . import audit

    records = audit.read(log)
    selected = [(record, records[record])] if record is not None else list(enumerate(records))
    client = LLMClient()  # replays are not themselves appended to the log
    same = 0
    for i, rec in selected:
        answer = _guard(lambda rec=rec: client.replay(rec))
        identical = audit.sha256_text(answer) == rec["response_sha256"]
        same += identical
        console.print(
            f"#{i} {rec['operation']} {rec['model_alias']}: "
            + ("[green]identical[/green]" if identical else "[yellow]different[/yellow]")
        )
    console.print(f"{same}/{len(selected)} answer(s) reproduced byte for byte")


def main() -> None:  # pragma: no cover
    sys.exit(app())
