import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from dfirassist import audit
from dfirassist.assistant import Investigation
from dfirassist.cli import app
from dfirassist.llm import LLMClient, MockBackend, Settings

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _audited_run(tmp_path: Path) -> tuple[Path, Path]:
    case = tmp_path / "case"
    shutil.copytree(SAMPLES / "win-rdp-intrusion", case)
    log = tmp_path / "audit.jsonl"
    client = LLMClient(
        Settings(backend="mock"), backend=MockBackend(), audit=audit.AuditLog(log, case_id="CASE-1")
    )
    inv = Investigation.from_paths([case], client=client)
    inv.summarize()
    inv.ask("Which account was used?")
    return log, case


def test_every_model_call_is_recorded(tmp_path):
    log, case = _audited_run(tmp_path)
    records = audit.read(log)
    assert [r["operation"] for r in records] == ["summarize", "ask"]
    rec = records[0]
    assert rec["case_id"] == "CASE-1"
    assert rec["params"] == {"temperature": 0.0, "seed": 42, "json_mode": True}
    assert rec["prompt_version"] and rec["tool"].startswith("dfir-llm-assistant")
    hashed = {Path(i["path"]).name: i["sha256"] for i in rec["inputs"]}
    assert hashed["Security.jsonl"] == audit.sha256_file(case / "Security.jsonl")
    assert rec["response_sha256"] == audit.sha256_text(rec["response"])
    assert records[1]["prev_hash"] == rec["record_hash"]


def test_verify_detects_tampering_and_changed_inputs(tmp_path):
    log, case = _audited_run(tmp_path)
    assert audit.verify(log).chain_ok
    lines = log.read_text().splitlines()
    first = json.loads(lines[0])
    first["response"] = first["response"].replace("malicious", "benign")
    log.write_text(json.dumps(first) + "\n" + lines[1] + "\n")
    result = audit.verify(log)
    assert not result.chain_ok and result.broken_at == 0

    log2, case2 = _audited_run(tmp_path / "b")
    with (case2 / "System.jsonl").open("a") as handle:
        handle.write("{}\n")
    assert any("content changed" in m for m in audit.verify(log2).input_mismatches)


def test_replay_reproduces_deterministic_backend(tmp_path):
    log, _ = _audited_run(tmp_path)
    client = LLMClient(Settings(backend="mock"), backend=MockBackend())
    for rec in audit.read(log):
        assert audit.sha256_text(client.replay(rec)) == rec["response_sha256"]


def test_cli_writes_and_verifies_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("DFA_BACKEND", "mock")
    log = tmp_path / "trail.jsonl"
    runner = CliRunner()
    out = runner.invoke(app, ["--audit-log", str(log), "summarize", str(SAMPLES / "win-rdp-intrusion")])
    assert out.exit_code == 0, out.output
    assert "not evidence" in out.output
    assert len(audit.read(log)) == 1
    out = runner.invoke(app, ["audit", "verify", str(log)])
    assert out.exit_code == 0 and "intact" in out.output
    out = runner.invoke(app, ["audit", "replay", str(log)])
    assert "1/1" in out.output
