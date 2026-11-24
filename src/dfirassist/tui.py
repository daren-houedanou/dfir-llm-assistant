"""Textual TUI: findings on the left, events in the middle, chat with the model at the bottom."""

from __future__ import annotations

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Markdown, Static

from .assistant import Investigation
from .detect import attack
from .llm import GatewayError, PolicyError


class DfirApp(App):
    TITLE = "dfir-llm-assistant"
    CSS = """
    #left { width: 38%; }
    #findings { height: 1fr; border: round $error; }
    #events { height: 1fr; border: round $primary; }
    #answer { height: 1fr; border: round $success; padding: 0 1; overflow-y: auto; }
    #status { height: 1; color: $text-muted; }
    Input { dock: bottom; }
    """
    BINDINGS = [
        Binding("s", "summarize", "Summarize"),
        Binding("f", "filter_finding", "Events of finding"),
        Binding("a", "all_events", "All events"),
        Binding("slash", "focus_input", "Ask"),
        Binding("escape", "focus_findings", "Back to findings", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, investigation: Investigation):
        super().__init__()
        self.inv = investigation
        self.last_answer = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="left"):
                yield DataTable(id="findings", cursor_type="row")
                yield DataTable(id="events", cursor_type="row")
            yield Markdown(self._welcome(), id="answer")
        yield Static("", id="status")
        yield Input(
            placeholder="Ask about the artifacts, or: /query <target> <need>   (targets: spl kql eql sigma jq zeek)"
        )
        yield Footer()

    def _welcome(self) -> str:
        policy = (
            "cloud allowed (pseudonymized)" if self.inv.allow_cloud else "confidential: local models only"
        )
        return (
            f"# Investigation\n{len(self.inv.events)} events, {len(self.inv.findings)} deterministic finding(s).\n\n"
            f"Policy: **{policy}**\n\nPress **s** for an incident summary, **/** to ask a question."
        )

    def on_mount(self) -> None:
        findings = self.query_one("#findings", DataTable)
        findings.add_columns("sev", "finding", "ATT&CK")
        for i, f in enumerate(self.inv.findings):
            findings.add_row(f.severity, f.title, ", ".join(f.techniques), key=str(i))
        events = self.query_one("#events", DataTable)
        events.add_columns("time", "host", "type", "detail")
        self._show_events(self.inv.events[:500])
        findings.focus()  # keyboard shortcuts must not be typed into the input box

    def action_focus_findings(self) -> None:
        self.query_one("#findings", DataTable).focus()

    def _show_events(self, events) -> None:
        table = self.query_one("#events", DataTable)
        table.clear()
        for e in events:
            table.add_row(
                f"{e.timestamp:%m-%d %H:%M:%S}" if e.timestamp else "?",
                (e.host or "")[:18],
                e.event_type,
                (e.user or e.src_ip or e.message)[:60],
            )

    def action_filter_finding(self) -> None:
        table = self.query_one("#findings", DataTable)
        if table.row_count:
            finding = self.inv.findings[table.cursor_row]
            self._show_events(finding.evidence)
            techs = "\n".join(f"- **{t}** {attack.name(t)}" for t in finding.techniques)
            self.query_one("#answer", Markdown).update(
                f"## {finding.title}\n{finding.description}\n\n{techs}"
            )

    def action_all_events(self) -> None:
        self._show_events(self.inv.events[:500])

    def action_focus_input(self) -> None:
        self.query_one(Input).focus()

    def action_summarize(self) -> None:
        self._status("summarizing...")
        self._run("summary", "")

    @on(Input.Submitted)
    def submitted(self, message: Input.Submitted) -> None:
        text = message.value.strip()
        message.input.value = ""
        if not text:
            return
        self._status("thinking...")
        if text.startswith("/query"):
            parts = text.split(maxsplit=2)
            if len(parts) < 3:
                self._status("usage: /query <target> <need>")
                return
            self._run("query", parts[2], parts[1])
        else:
            self._run("ask", text)

    def _status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    @work(thread=True, exclusive=True)
    def _run(self, kind: str, text: str, target: str = "") -> None:
        try:
            if kind == "summary":
                report = self.inv.summarize()
                d = report.data
                md = [
                    f"# Verdict: {d.get('verdict')} ({d.get('confidence')})",
                    d.get("summary", ""),
                    "## ATT&CK",
                ]
                md += [
                    f"- **{t.get('id')}** {t.get('name', '')}"
                    for t in d.get("techniques", [])
                    if isinstance(t, dict)
                ]
                md += ["## IOCs"] + [
                    f"- {i.get('type')}: `{i.get('value')}`" for i in d.get("iocs", []) if isinstance(i, dict)
                ]
                md += ["## Next steps"] + [f"- {s}" for s in d.get("next_steps", [])]
                if report.ungrounded_iocs:
                    md.append(f"\n> ⚠ not found in artifacts: {', '.join(report.ungrounded_iocs)}")
                md.append(
                    "\n_LLM-generated analytic aid, not evidence: verify against [F#] and the artifacts._"
                )
                completion = report.completion
                body = "\n".join(md)
            elif kind == "query":
                result = self.inv.generate_query(text, target)
                completion = result.completion
                body = f"## {target} query\n```\n{result.query}\n```\n{result.explanation}\n\n" + (
                    "✅ syntax valid" if result.valid else f"❌ {result.error}"
                )
            else:
                completion = self.inv.ask(text)
                body = f"**Q:** {text}\n\n{completion.text}"
            status = f"{completion.model} · {completion.latency_s:.1f}s · " + (
                "pseudonymized" if completion.pseudonymized else "local-only"
            )
        except (PolicyError, GatewayError, ValueError) as exc:
            body, status = f"## Error\n{exc}", "error"
        self.last_answer = body  # kept for tests and for copy/export
        self.call_from_thread(self.query_one("#answer", Markdown).update, body)
        self.call_from_thread(self._status, status)


def run(investigation: Investigation) -> None:
    DfirApp(investigation).run()
