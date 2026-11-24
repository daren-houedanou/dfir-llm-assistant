from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import httpx
import pytest
import yaml

from dfirassist import parsers
from dfirassist.assistant import Investigation, validate_query
from dfirassist.context import build
from dfirassist.detect import attack, rules
from dfirassist.eval.harness import Scenario, run_suite, score_techniques
from dfirassist.llm import LLMClient, MockBackend, PolicyError, Settings, extract_json
from dfirassist.models import Event
from dfirassist.parsers.common import parse_ts
from dfirassist.privacy import Pseudonymizer

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def mock_client(**kw) -> LLMClient:
    return LLMClient(Settings(backend="mock", **kw), backend=MockBackend())


# ----------------------------------------------------------------------------- parsers


@pytest.mark.parametrize(
    "path,fmt",
    [
        (SAMPLES / "win-rdp-intrusion/Security.jsonl", "evtx"),
        (SAMPLES / "linux-ssh-compromise/auth.log", "linux"),
        (SAMPLES / "linux-ssh-compromise/timeline.body", "timeline"),
        (SAMPLES / "network-c2-exfil/conn.log", "zeek"),
        (SAMPLES / "win-memory-phishing/windows.pslist.json", "memory"),
        (SAMPLES / "win-memory-phishing/windows.malfind.json", "memory"),
    ],
)
def test_format_detection(path, fmt):
    assert parsers.detect_format(path) == fmt


def test_evtx_fields():
    events = list(parsers.parse_file(SAMPLES / "win-rdp-intrusion/Security.jsonl"))
    failure = next(e for e in events if e.event_type == "Security/4625")
    assert failure.src_ip == "203.0.113.45"
    assert failure.host == "WS-FIN-042.corp.example.lan"
    assert failure.timestamp.tzinfo is not None
    group_add = next(e for e in events if e.event_type == "Security/4732")
    assert group_add.user != "Administrators"  # TargetUserName is the group, not the member


def test_evtx_dump_json_format(tmp_path):
    """`evtx_dump -o json` prints 'Record N' headers between pretty-printed objects."""
    rec = json.loads((SAMPLES / "win-rdp-intrusion/System.jsonl").read_text().splitlines()[0])
    p = tmp_path / "System.json"
    p.write_text(f"Record 1\n{json.dumps(rec, indent=2)}\nRecord 2\n{json.dumps(rec, indent=2)}\n")
    events = list(parsers.parse_file(p, "evtx"))
    assert len(events) == 2 and events[0].event_type == "System/7045"


def test_linux_classification():
    events = list(parsers.parse_file(SAMPLES / "linux-ssh-compromise/auth.log"))
    types = {e.event_type for e in events}
    assert {"sshd/failed_password", "sshd/accepted", "sudo/command", "useradd/new_user", "cron/cmd"} <= types
    accepted = [(e.user, e.src_ip) for e in events if e.event_type == "sshd/accepted"]
    assert ("deploy", "198.51.100.23") in accepted


def test_plaso_l2tcsv(tmp_path):
    p = tmp_path / "timeline.csv"
    p.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"
        "10/14/2026,01:22:00,UTC,M...,FILE,NTFS,Content Modification Time,-,WS01,x,C:/Users/Public/a.exe,2,-,-,-,-,-\n"
    )
    (event,) = parsers.parse_file(p)
    assert event.event_type == "plaso/FILE" and event.timestamp.hour == 1


def test_parse_ts_variants():
    assert parse_ts("2026-10-14T01:12:03.1234567Z").microsecond == 123456
    assert parse_ts("1762074000.123").year == 2025
    assert parse_ts("Oct 20 22:40:00", default_year=2026).month == 10
    assert parse_ts("-") is None


# ----------------------------------------------------------------------------- detection


def _techniques(name: str) -> set[str]:
    return {t for f in rules.run_all(parsers.load([SAMPLES / name])) for t in f.techniques}


def test_rules_windows():
    assert {"T1110.001", "T1078", "T1021.001", "T1136.001", "T1543.003", "T1070.001"} <= _techniques(
        "win-rdp-intrusion"
    )


def test_rules_linux():
    assert {"T1110.001", "T1021.004", "T1053.003", "T1548.003", "T1070.002"} <= _techniques(
        "linux-ssh-compromise"
    )


def test_rules_network():
    assert {"T1071.001", "T1071.004", "T1048"} <= _techniques("network-c2-exfil")


def test_rules_memory():
    assert {"T1204.002", "T1059.001", "T1027", "T1105", "T1036.005", "T1055", "T1071.001"} <= _techniques(
        "win-memory-phishing"
    )


def test_volatility_pstree_and_jsonl(tmp_path):
    tree = [
        {
            "PID": 2164,
            "PPID": 2140,
            "ImageFileName": "explorer.exe",
            "CreateTime": "2026-01-01T09:00:00",
            "__children": [
                {
                    "PID": 3412,
                    "PPID": 2164,
                    "ImageFileName": "WINWORD.EXE",
                    "CreateTime": None,
                    "__children": [
                        {
                            "PID": 4720,
                            "PPID": 3412,
                            "ImageFileName": "cmd.exe",
                            "CreateTime": None,
                            "__children": [],
                        }
                    ],
                }
            ],
        }
    ]
    (tmp_path / "pstree.json").write_text("\n" + json.dumps(tree, indent=2, sort_keys=True))
    (tmp_path / "pstree.jsonl").write_text(json.dumps(tree[0], sort_keys=True) + "\n")
    for name in ("pstree.json", "pstree.jsonl"):
        events = list(parsers.parse_file(tmp_path / name))
        assert [e.fields["pid"] for e in events] == [2164, 3412, 4720]
        assert parsers.detect_format(tmp_path / name) == "memory"
    finding = rules.memory_process_tree(events)[0]
    assert finding.techniques == ["T1059.003", "T1204.002"]


def _proc(pid, ppid, name, exited=False) -> Event:
    return Event(
        None,
        "memory",
        "memory/process",
        process=name,
        fields={"pid": pid, "ppid": ppid, "exit_time": "x" if exited else None},
    )


def test_memory_rules_avoid_common_false_positives():
    normal = [
        _proc(504, 420, "wininit.exe"),
        _proc(640, 504, "services.exe"),
        _proc(652, 504, "lsass.exe"),
        _proc(788, 640, "svchost.exe"),
        _proc(2164, 2140, "explorer.exe"),
        _proc(3100, 2164, "chrome.exe"),
        _proc(3200, 3100, "chrome.exe"),
    ]
    assert rules.memory_process_tree(normal) == []
    jit = Event(
        None,
        "memory",
        "memory/malfind",
        process="chrome.exe",
        fields={"pid": 3100, "protection": "PAGE_EXECUTE_READWRITE", "mz_header": False},
    )
    assert rules.memory_code_injection([jit])[0].severity == "medium"
    internal = Event(None, "memory", "memory/netconn", dst_ip="10.0.0.5", dst_port=445, process="cmd.exe")
    assert rules.memory_suspicious_connection([internal]) == []


def test_memory_masquerading_names():
    procs = [
        _proc(640, 504, "services.exe"),
        _proc(900, 640, "svch0st.exe"),
        _proc(652, 504, "lsass.exe"),
        _proc(990, 640, "lsass.exe"),
    ]
    text = rules.memory_process_tree(procs)[0].description
    assert "svch0st.exe" in text and "2 running lsass.exe" in text


def test_rules_no_false_positive_on_benign():
    assert rules.run_all(parsers.load([SAMPLES / "benign-admin-day"])) == []


def _evtx(event_type: str, **fields) -> Event:
    return Event(
        timestamp=parse_ts("2026-01-01T10:00:00Z"),
        source="evtx",
        event_type=event_type,
        user=fields.get("TargetUserName"),
        src_ip=fields.get("IpAddress"),
        process=fields.get("Image"),
        fields=fields,
    )


def test_rule_kerberos_spray():
    users = ["alice", "bob", "carol", "dave", "erin"]
    events = [
        _evtx("Security/4771", TargetUserName=u, IpAddress="::ffff:10.0.0.9", Status="0x18") for u in users
    ]
    finding = next(f for f in rules.run_all(events) if f.rule == "kerberos_spray")
    assert finding.techniques == ["T1110.003"] and finding.indicators["ip"] == ["10.0.0.9"]
    # A handful of typos on one or two accounts is not a spray.
    assert not any(f.rule == "kerberos_spray" for f in rules.run_all(events[:2]))
    # Successful TGT requests are not failures.
    ok = [_evtx("Security/4768", TargetUserName=u, IpAddress="10.0.0.9", Status="0x0") for u in users]
    assert not any(f.rule == "kerberos_spray" for f in rules.run_all(ok))


def test_rule_fake_computer_account():
    finding = rules.run_all([_evtx("Security/4720", TargetUserName="srv01$")])[0]
    assert finding.severity == "high" and "computer" in finding.title
    assert rules.run_all([_evtx("Security/4720", TargetUserName="jdoe")])[0].severity == "medium"


def test_rule_service_running_an_interpreter():
    def sev(image_path: str) -> str:
        return rules.run_all([_evtx("System/7045", ServiceName="x", ImagePath=image_path)])[0].severity

    assert sev("cmd.exe") == "high"
    assert sev("%COMSPEC% /Q /c echo whoami") == "high"
    assert sev(r"C:\Windows\System32\rundll32.exe evil.dll,Run") == "high"
    assert sev(r'"C:\Program Files\Vendor\agent.exe" -service') == "low"


def test_rule_powershell_reverse_shell():
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    child = _evtx("Sysmon/1", Image=r"C:\Windows\System32\cmd.exe", ParentImage=ps)
    conn = _evtx("Sysmon/3", Image=ps)
    finding = next(f for f in rules.run_all([child, conn]) if f.rule == "powershell_activity")
    assert finding.severity == "high" and finding.techniques == ["T1059.001"]
    alone = next(f for f in rules.run_all([child]) if f.rule == "powershell_activity")
    assert alone.severity == "medium"


def test_powershell_decoding():
    findings = rules.run_all(parsers.load([SAMPLES / "win-rdp-intrusion"]))
    sus = next(f for f in findings if f.rule == "suspicious_execution")
    assert "http://198.51.100.77/a.ps1" in sus.indicators["url"]


def test_attack_catalog():
    assert attack.extract_ids("seen T1059.001 and T1078.") == {"T1059.001", "T1078"}
    assert attack.is_known("T1110.001") and not attack.is_known("T9999")


# ----------------------------------------------------------------------------- context & privacy


def test_context_respects_budget():
    events = parsers.load([SAMPLES])
    ctx = build(events, rules.run_all(events), budget_tokens=1500)
    assert ctx.tokens <= 1700
    assert "[F1]" in ctx.text and ctx.events_included < ctx.events_total


def test_pseudonymizer_roundtrip():
    events = parsers.load([SAMPLES / "win-rdp-intrusion"])
    p = Pseudonymizer()
    for e in events:
        p.register_event(e)
    text = "m.durand on WS-FIN-042.corp.example.lan from 203.0.113.45 and 10.0.0.3 mail bob@corp.example.lan"
    masked = p.mask(text)
    for secret in ("m.durand", "WS-FIN-042", "203.0.113.45", "10.0.0.3", "bob@"):
        assert secret.lower() not in masked.lower()
    assert "IP_PUB_" in masked and "IP_PRIV_" in masked  # semantics preserved
    assert p.unmask(masked) == text
    assert p.leaked(masked) == []


def test_cloud_prompt_has_no_raw_identifiers():
    inv = Investigation(
        parsers.load([SAMPLES / "win-rdp-intrusion"]), mock_client(), allow_cloud=True, model="dfir-cloud"
    )
    report = inv.summarize()
    assert report.completion.pseudonymized
    sent = report.completion.sent_prompt
    assert "203.0.113.45" not in sent and "WS-FIN-042" not in sent and "m.durand" not in sent
    assert inv.pseudonymizer.leaked(sent) == []
    # answer is rehydrated locally
    assert any(i["value"] == "203.0.113.45" for i in report.data["iocs"])


# ----------------------------------------------------------------------------- policy & LLM plumbing


def test_policy_blocks_cloud_for_confidential_case():
    client = mock_client()
    with pytest.raises(PolicyError):
        client.complete("s", "p", model="dfir-cloud", allow_cloud=False)
    alias, masked = client.resolve(None, allow_cloud=False)
    assert alias == "dfir-local" and not masked


def test_extract_json_tolerates_chatter():
    assert extract_json('Sure!\n```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('blah {"a": {"b": 2}} trailing') == {"a": {"b": 2}}


class FlakyBackend:
    """First answer is broken JSON, second is valid: exercises the repair round."""

    def __init__(self):
        self.calls = 0

    def chat(self, model, messages, json_mode):
        self.calls += 1
        if self.calls == 1:
            return "I think it is malicious", {}, model
        return (
            json.dumps(
                {
                    "summary": "x",
                    "verdict": "malicious",
                    "techniques": [{"id": "T1078"}, {"id": "T9999"}],
                    "iocs": [{"type": "ip", "value": "203.0.113.45"}, {"type": "ip", "value": "6.6.6.6"}],
                    "next_steps": [],
                }
            ),
            {},
            model,
        )


def test_summarize_repairs_and_flags_hallucinations():
    backend = FlakyBackend()
    inv = Investigation(parsers.load([SAMPLES / "win-rdp-intrusion"]), LLMClient(Settings(), backend=backend))
    report = inv.summarize()
    assert backend.calls == 2 and report.repaired
    assert report.unknown_techniques == ["T9999"]
    assert report.ungrounded_iocs == ["6.6.6.6"]


def test_litellm_backend_wire_format():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "model": "dfir-local",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 1},
            },
        )

    settings = Settings(backend="litellm", api_key="sk-x", gateway_url="http://gw")
    client = LLMClient(settings)
    client.backend.client = httpx.Client(
        base_url="http://gw", transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer sk-x"}
    )
    out = client.complete("sys", "hello")
    assert out.text == "ok" and out.prompt_tokens == 12
    assert seen["body"]["model"] == "dfir-local" and seen["body"]["temperature"] == 0
    assert seen["body"]["seed"] == 42  # fixed seed for reproducibility
    assert seen["auth"] == "Bearer sk-x"


# ----------------------------------------------------------------------------- query generation


def test_validate_sigma():
    good = "title: t\nlogsource: {product: windows}\ndetection:\n  sel: {EventID: 4625}\n  condition: sel\n"
    assert validate_query("sigma", good) is None
    assert "condition" in validate_query("sigma", "title: t\nlogsource: {}\ndetection: {sel: 1}\n")


@pytest.mark.skipif(not shutil.which("jq"), reason="jq not installed")
def test_jq_query_generation_and_execution():
    inv = Investigation(parsers.load([SAMPLES / "win-rdp-intrusion"]), mock_client())
    result = inv.generate_query(
        "failed logons", "jq", test_files=[SAMPLES / "win-rdp-intrusion/Security.jsonl"]
    )
    assert result.valid and result.hits == 45
    assert validate_query("jq", "select(.a ==") is not None


# ----------------------------------------------------------------------------- evaluation


def test_scenarios_are_consistent():
    for f in (ROOT / "eval/scenarios").glob("*.yaml"):
        s = Scenario.load(f)
        assert all(a.exists() for a in s.artifacts), f
        assert all(attack.is_known(t) for t in s.techniques), f


def test_score_techniques():
    assert score_techniques({"T1110.003"}, {"T1110.001"}) == (0.0, 0.0, 1.0)
    assert score_techniques(set(), set()) == (1.0, 1.0, 1.0)


def test_eval_suite_rules_baseline():
    results = run_suite(ROOT / "eval/scenarios", models=[])
    assert len(results) == 5 and all(r.error is None for r in results)
    assert all(r.verdict_ok for r in results)
    assert all(r.leaks == 0 for r in results)


# ----------------------------------------------------------------------------- deployment


def test_kustomize_configs_in_sync():
    assert (ROOT / "deploy/k8s/base/litellm-config.yaml").read_text() == (
        ROOT / "deploy/litellm/config.local-only.yaml"
    ).read_text()
    assert (ROOT / "deploy/k8s/overlays/hybrid/litellm-config.yaml").read_text() == (
        ROOT / "deploy/litellm/config.yaml"
    ).read_text()


def test_air_gapped_config_has_no_cloud_model():
    cfg = yaml.safe_load((ROOT / "deploy/litellm/config.local-only.yaml").read_text())
    for m in cfg["model_list"]:
        assert m["model_name"].startswith("dfir-local")
        assert m["litellm_params"]["model"].startswith("ollama")


def test_fallbacks_never_cross_confidentiality_boundary():
    cfg = yaml.safe_load((ROOT / "deploy/litellm/config.yaml").read_text())
    for rule in cfg["router_settings"]["fallbacks"]:
        for primary, fallbacks in rule.items():
            if primary.startswith("dfir-local"):
                assert all(f.startswith("dfir-local") for f in fallbacks)


@pytest.mark.skipif(
    not os.environ.get("DFA_IT_GATEWAY"), reason="set DFA_IT_GATEWAY to a running LiteLLM proxy"
)
def test_integration_real_gateway():
    settings = Settings(
        backend="litellm", gateway_url=os.environ["DFA_IT_GATEWAY"], api_key=os.environ.get("DFA_API_KEY", "")
    )
    inv = Investigation(parsers.load([SAMPLES / "win-rdp-intrusion"]), LLMClient(settings))
    report = inv.summarize()
    assert report.data["verdict"]


def test_verdict_scores_exact_and_lenient():
    from dfirassist.eval.harness import verdict_scores

    assert verdict_scores("malicious", "malicious") == (True, True)
    assert verdict_scores("suspicious", "malicious") == (False, True)
    assert verdict_scores("benign", "malicious") == (False, False)
    assert verdict_scores("suspicious", "benign") == (False, False)
    assert verdict_scores("benign", "benign") == (True, True)


def test_eval_model_calls_are_audited(tmp_path, monkeypatch):
    from pathlib import Path

    from dfirassist.audit import AuditLog
    from dfirassist.eval.harness import run_suite

    monkeypatch.setenv("DFA_BACKEND", "mock")
    log = AuditLog(tmp_path / "audit.jsonl")
    scenario = Path(__file__).parent.parent / "eval/scenarios/win-rdp-intrusion.yaml"
    results = run_suite(scenario, ["dfir-local"], audit=log)
    assert {r.model for r in results} == {"rules", "dfir-local"}
    assert all(r.verdict_given for r in results)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert lines, "model calls made by dfa eval must be in the audit trail"
