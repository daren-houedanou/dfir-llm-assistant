"""Deterministic detection rules run before any LLM call.

Why rules first?  They are cheap, explainable and reproducible. Their findings are
(1) shown to the analyst directly (``dfa triage``), and (2) injected into the LLM
context as anchored evidence, which reduces hallucinations and token usage. The
evaluation harness measures both the rules alone and rules + LLM.
"""

from __future__ import annotations

import base64
import ipaddress
import math
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import timedelta

from ..models import SEVERITY_ORDER, Event, Finding
from ..privacy import INTERNAL_NETS

Rule = Callable[[list[Event]], list[Finding]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _of_type(events: list[Event], *types: str) -> list[Event]:
    return [e for e in events if e.event_type in types]


# --------------------------------------------------------------------------- credential access


@rule
def brute_force(events: list[Event]) -> list[Finding]:
    """Many failed logons from one source, optionally followed by a success (Windows and SSH)."""
    # sshd logs "Invalid user" *and* "Failed password for invalid user" for one attempt: count the latter only.
    failures = _of_type(events, "Security/4625", "sshd/failed_password")
    successes = _of_type(events, "Security/4624", "sshd/accepted")
    by_src: dict[str, list[Event]] = defaultdict(list)
    for e in failures:
        if e.src_ip:
            by_src[e.src_ip].append(e)
    findings = []
    for src, fails in by_src.items():
        if len(fails) < 10:
            continue
        users = Counter(e.user for e in fails if e.user)
        last_fail = max(e.timestamp for e in fails if e.timestamp)
        followed = [
            s
            for s in successes
            if s.src_ip == src and s.timestamp and s.timestamp >= last_fail - timedelta(minutes=5)
        ]
        windows = fails[0].source == "evtx"
        # Spraying = many accounts, few attempts each; guessing = many attempts per account.
        spray = len(users) >= 5 and len(fails) / len(users) <= 3
        technique = "T1110.003" if spray else "T1110.001"
        techniques = [technique]
        sev = "medium"
        desc = f"{len(fails)} failed logons from {src} targeting {len(users)} account(s) ({', '.join(u for u, _ in users.most_common(3))})."
        if followed:
            sev = "critical"
            ok = followed[0]
            desc += f" Followed by a SUCCESSFUL logon as {ok.user} at {ok.timestamp:%Y-%m-%d %H:%M:%S}Z."
            techniques.append("T1078")
            if windows and str(ok.fields.get("LogonType")) == "10":
                techniques.append("T1021.001")
            if not windows:
                techniques.append("T1021.004")
        findings.append(
            Finding(
                rule="brute_force",
                title="Password spraying" if spray else "Password brute force",
                severity=sev,
                techniques=techniques,
                description=desc,
                evidence=fails[:5] + followed[:3],
                indicators={"ip": [src], "user": sorted({*users, *(s.user for s in followed if s.user)})},
            )
        )
    return findings


# Kerberos result codes that mean "wrong user or wrong password" (RFC 4120 / MS-KILE):
# unknown principal, revoked, expired password, bad password.
KERBEROS_FAILURE_CODES = {"0x6", "0x12", "0x17", "0x18"}


def _norm_ip(ip: str | None) -> str | None:
    return ip[7:] if ip and ip.lower().startswith("::ffff:") else ip


@rule
def kerberos_spray(events: list[Event]) -> list[Finding]:
    """Kerberos pre-authentication failures (4771) and failed TGT requests (4768) against many accounts.

    Spraying tries one or two passwords on many accounts, so the per-source volume stays below
    the generic brute-force threshold; the number of distinct accounts is what gives it away.
    """
    failures = [
        e
        for e in _of_type(events, "Security/4771", "Security/4768")
        if str(e.fields.get("Status", "")).lower() in KERBEROS_FAILURE_CODES
    ]
    by_src: dict[str, list[Event]] = defaultdict(list)
    for e in failures:
        src = _norm_ip(e.src_ip)
        if src:
            by_src[src].append(e)
    findings = []
    for src, fails in by_src.items():
        users = sorted({e.user for e in fails if e.user})
        if len(users) < 5:
            continue
        bad_password = [e for e in fails if str(e.fields.get("Status", "")).lower() == "0x18"]
        findings.append(
            Finding(
                rule="kerberos_spray",
                title="Kerberos password spraying",
                severity="high",
                techniques=["T1110.003"],
                description=f"{len(fails)} failed Kerberos authentications from {src} against {len(users)} "
                f"accounts ({', '.join(users[:5])}); {len(bad_password)} with a wrong password (0x18).",
                evidence=fails[:6],
                indicators={"ip": [src], "user": users},
            )
        )
    return findings


# --------------------------------------------------------------------------- persistence


@rule
def account_creation(events: list[Event]) -> list[Finding]:
    created = _of_type(events, "Security/4720", "useradd/new_user")
    if not created:
        return []
    group_adds = _of_type(events, "Security/4728", "Security/4732", "Security/4756", "usermod/group_add")
    privileged = [
        g
        for g in group_adds
        if re.search(
            r"admin|sudo|wheel|root|domain admins",
            f"{g.message} {g.fields.get('group', '')} {g.fields.get('TargetUserName', '')}",
            re.I,
        )
    ]
    users = sorted(
        {
            e.fields.get("TargetUserName") or e.user
            for e in created
            if (e.fields.get("TargetUserName") or e.user)
        }
    )
    techniques = ["T1136.001"] + (["T1098"] if privileged else [])
    # Machine accounts end with "$" and are created through 4741, never through the user-creation
    # event 4720: a 4720 for a "$" name is an account hiding among computer accounts.
    fake_machine = sorted(
        {
            str(e.fields.get("TargetUserName") or e.user)
            for e in created
            if e.event_type == "Security/4720" and str(e.fields.get("TargetUserName") or e.user).endswith("$")
        }
    )
    title = "Local account created" + (" and added to a privileged group" if privileged else "")
    if fake_machine:
        title = "User account disguised as a computer account"
    return [
        Finding(
            rule="account_creation",
            title=title,
            severity="high" if privileged or fake_machine else "medium",
            techniques=techniques,
            description=f"New account(s): {', '.join(users)}."
            + (f" {len(privileged)} privileged group membership change(s)." if privileged else "")
            + (
                f" {', '.join(fake_machine)}: name ending with $ created as a user (4720), "
                "not as a computer (4741)."
                if fake_machine
                else ""
            ),
            evidence=created + privileged,
            indicators={"user": users},
        )
    ]


SUSPICIOUS_CMD = re.compile(
    r"(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|"
    r"/tmp/|/dev/shm/|\\temp\\|\\users\\public\\|curl\s+[^|]*\|\s*(ba)?sh|wget\s+|nc\s+-e|bash\s+-i|/dev/tcp/)",
    re.I,
)


# A service binary should be a service executable, not a shell or a script host: PsExec-like tools,
# Impacket smbexec / services.py and most remote-execution frameworks install exactly this.
SERVICE_INTERPRETER = re.compile(
    r"""^["'\s]*(%comspec%|(\S*\\)?(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript)(\.exe)?\b)""",
    re.I,
)


@rule
def service_or_task_persistence(events: list[Event]) -> list[Finding]:
    findings = []
    services = _of_type(events, "System/7045")
    for e in services:
        image = str(e.fields.get("ImagePath", ""))
        sus = bool(SUSPICIOUS_CMD.search(image) or SERVICE_INTERPRETER.search(image))
        findings.append(
            Finding(
                rule="service_install",
                title=f"Service installed: {e.fields.get('ServiceName', '?')}",
                severity="high" if sus else "low",
                techniques=["T1543.003"] + (["T1059.001"] if "powershell" in image.lower() else []),
                description=f"ImagePath: {image[:200]}",
                evidence=[e],
                indicators={"service": [str(e.fields.get("ServiceName", ""))]},
            )
        )
    tasks = _of_type(events, "Security/4698")
    for e in tasks:
        findings.append(
            Finding(
                rule="scheduled_task",
                title=f"Scheduled task created: {e.fields.get('TaskName', '?')}",
                severity="medium",
                techniques=["T1053.005"],
                description=e.message,
                evidence=[e],
            )
        )
    cron_edits = _of_type(events, "cron/edit")
    cron_cmds = [
        e for e in _of_type(events, "cron/cmd") if SUSPICIOUS_CMD.search(str(e.fields.get("command", "")))
    ]
    if cron_edits or cron_cmds:
        findings.append(
            Finding(
                rule="cron_persistence",
                title="Crontab modified" + (" with suspicious command" if cron_cmds else ""),
                severity="high" if cron_cmds else "medium",
                techniques=["T1053.003"],
                description="; ".join(
                    str(e.fields.get("command") or e.message) for e in (cron_cmds or cron_edits)[:3]
                ),
                evidence=cron_edits + cron_cmds[:5],
                indicators={"user": sorted({e.user for e in cron_edits + cron_cmds if e.user})},
            )
        )
    return findings


WELL_KNOWN_RISKY_SIDS = {
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
}


@rule
def privileged_group_change(events: list[Event]) -> list[Finding]:
    """Membership added to an admin group for an *existing* principal (creation is covered above)."""
    if _of_type(events, "Security/4720", "useradd/new_user"):
        return []
    adds = _of_type(events, "Security/4728", "Security/4732", "Security/4756", "usermod/group_add")
    privileged = [
        g
        for g in adds
        if re.search(
            r"admin|sudo|wheel|root",
            f"{g.fields.get('TargetUserName', '')} {g.fields.get('group', '')}",
            re.I,
        )
    ]
    if not privileged:
        return []
    members = []
    risky = False
    for g in privileged:
        sid = str(g.fields.get("MemberSid", ""))
        if sid in WELL_KNOWN_RISKY_SIDS or sid.endswith("-501"):  # -501 = built-in Guest
            risky = True
            members.append(WELL_KNOWN_RISKY_SIDS.get(sid, "Guest") + f" ({sid})")
        else:
            members.append(g.user or sid or "?")
    return [
        Finding(
            rule="privileged_group_change",
            title="Principal added to a privileged group",
            severity="high" if risky else "medium",
            techniques=["T1098"],
            description=f"Added to admin group: {', '.join(members)}"
            + (" (built-in/service principal: highly unusual)" if risky else ""),
            evidence=privileged,
            indicators={"user": sorted({g.fields.get("SubjectUserName") or "" for g in privileged} - {""})},
        )
    ]


# --------------------------------------------------------------------------- credential dumping & discovery

LSASS_DUMP = re.compile(
    r"(minidumpwritedump|comsvcs(\.dll)?[, ]+#?minidump|sekurlsa|procdump(64)?(\.exe)?\s+.*lsass|"
    r"rdrleakdiag|get-process\s+lsass|lsass.*\.dmp|out-minidump)",
    re.I,
)


@rule
def credential_dumping(events: list[Event]) -> list[Finding]:
    hits = []
    for e in events:
        text = " ".join(str(e.fields.get(k, "")) for k in ("ScriptBlockText", "CommandLine", "TargetImage"))
        if LSASS_DUMP.search(text) or (
            e.event_type == "Sysmon/10" and "lsass" in str(e.fields.get("TargetImage", "")).lower()
        ):
            hits.append(e)
    if not hits:
        return []
    return [
        Finding(
            rule="credential_dumping",
            title="LSASS credential dumping",
            severity="critical",
            techniques=["T1003.001"]
            + (
                ["T1059.001"]
                if any(
                    e.event_type.startswith("PowerShell")
                    or "powershell" in str(e.fields.get("Image", "")).lower()
                    for e in hits
                )
                else []
            ),
            description=f"{len(hits)} event(s) referencing LSASS memory dumping.",
            evidence=hits[:5],
        )
    ]


DISCOVERY = {
    "T1033": re.compile(r"\bwhoami\b|\bquser\b", re.I),
    "T1082": re.compile(r"\bsysteminfo\b|\bhostname\b|\buname -a\b", re.I),
    "T1049": re.compile(r"\bnetstat\b|\bnet\s+session\b|\bss -", re.I),
    "T1087": re.compile(r"\bnet\s+(user|localgroup|group)\b|\bid\b|cat /etc/passwd", re.I),
    "T1482": re.compile(r"\bnltest\b.*(dclist|domain_trusts)", re.I),
}


@rule
def discovery_burst(events: list[Event]) -> list[Finding]:
    """Several reconnaissance commands on one host within 15 minutes (typical hands-on-keyboard)."""
    by_host: dict[str, list[tuple[Event, str]]] = defaultdict(list)
    for e in events:
        cmd = str(
            e.fields.get("CommandLine") or e.fields.get("command") or e.fields.get("ScriptBlockText") or ""
        )
        for tid, pattern in DISCOVERY.items():
            if cmd and pattern.search(cmd) and e.timestamp:
                by_host[e.host or "?"].append((e, tid))
    findings = []
    for host, hits in by_host.items():
        hits.sort(key=lambda x: x[0].timestamp)
        window = [h for h in hits if h[0].timestamp - hits[0][0].timestamp <= timedelta(minutes=15)]
        techniques = sorted({t for _, t in window})
        if len(window) >= 3 and len(techniques) >= 2:
            findings.append(
                Finding(
                    rule="discovery_burst",
                    title=f"Reconnaissance command burst on {host}",
                    severity="medium",
                    techniques=techniques,
                    description="; ".join(
                        sorted(
                            {
                                str(e.fields.get("CommandLine") or e.fields.get("command"))[:60]
                                for e, _ in window
                            }
                        )
                    )[:300],
                    evidence=[e for e, _ in window][:6],
                )
            )
    return findings


# --------------------------------------------------------------------------- execution


def _decode_powershell(text: str) -> str | None:
    match = re.search(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", text, re.I)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1)).decode("utf-16-le", errors="replace")
    except (ValueError, base64.binascii.Error):
        return None


URL_RE = re.compile(r"https?://[^\s'\"\)]+", re.I)


@rule
def suspicious_execution(events: list[Event]) -> list[Finding]:
    hits = []
    for e in events:
        text = " ".join(
            str(e.fields.get(k, "")) for k in ("ScriptBlockText", "CommandLine", "ImagePath", "command")
        )
        if text.strip() and SUSPICIOUS_CMD.search(text):
            hits.append((e, text))
    if not hits:
        return []
    techniques: set[str] = set()
    urls: set[str] = set()
    decoded = []
    for e, text in hits:
        lower = text.lower()
        if "powershell" in lower or e.event_type.startswith("PowerShell"):
            techniques.add("T1059.001")
        if e.source == "linux":
            techniques.add("T1059.004")
        if re.search(r"-enc|frombase64", lower):
            techniques.add("T1027")
        clear = _decode_powershell(text)
        if clear:
            decoded.append(clear[:200])
            text = f"{text} {clear}"
        found = URL_RE.findall(text)
        if found or re.search(r"downloadstring|downloadfile|wget |curl ", text, re.I):
            techniques.add("T1105")
        urls.update(found)
    desc = f"{len(hits)} command(s) with download, obfuscation or staging patterns."
    if decoded:
        desc += f" Decoded payload: {decoded[0]}"
    return [
        Finding(
            rule="suspicious_execution",
            title="Suspicious command execution",
            severity="high",
            techniques=sorted(techniques),
            description=desc,
            evidence=[e for e, _ in hits[:8]],
            indicators={"url": sorted(urls)},
        )
    ]


POWERSHELL_IMAGE = re.compile(r"\\(powershell|pwsh)(\.exe)?$", re.I)


@rule
def powershell_activity(events: list[Event]) -> list[Finding]:
    """PowerShell spawning shells or recon tools, and PowerShell opening network connections.

    Both together are the shape of a PowerShell reverse shell (powercat, Nishang, ...).
    """
    children = [
        e
        for e in _of_type(events, "Sysmon/1", "Security/4688")
        if POWERSHELL_IMAGE.search(
            str(e.fields.get("ParentImage") or e.fields.get("ParentProcessName") or "")
        )
    ]
    if not children:
        return []
    network = [
        e for e in _of_type(events, "Sysmon/3") if POWERSHELL_IMAGE.search(str(e.fields.get("Image", "")))
    ]
    names = sorted({str(e.process or e.fields.get("Image") or "?").rsplit("\\", 1)[-1] for e in children})
    reverse_shell = bool(network)
    return [
        Finding(
            rule="powershell_activity",
            title="PowerShell reverse shell pattern" if reverse_shell else "PowerShell spawning shells/tools",
            severity="high" if reverse_shell else "medium",
            techniques=["T1059.001"],
            description=f"powershell.exe started {', '.join(names)}"
            + (f" and opened {len(network)} network connection(s)." if reverse_shell else "."),
            evidence=(network[:2] + children)[:6],
            indicators={"ip": sorted({e.dst_ip for e in network if e.dst_ip})},
        )
    ]


@rule
def sudo_to_root(events: list[Event]) -> list[Finding]:
    sudo = [e for e in _of_type(events, "sudo/command") if e.fields.get("target") == "root"]
    risky = [
        e
        for e in sudo
        if re.search(
            r"/bin/(ba)?sh|su\b|useradd|crontab|chmod\s+[0-7]*s|visudo|/tmp/",
            str(e.fields.get("command", "")),
        )
    ]
    if not risky:
        return []
    return [
        Finding(
            rule="sudo_escalation",
            title="Privileged commands via sudo",
            severity="medium",
            techniques=["T1548.003"],
            description="; ".join(f"{e.user}: {e.fields.get('command')}" for e in risky[:4]),
            evidence=risky[:8],
            indicators={"user": sorted({e.user for e in risky if e.user})},
        )
    ]


# --------------------------------------------------------------------------- defense evasion


@rule
def log_clearing(events: list[Event]) -> list[Finding]:
    cleared = _of_type(events, "Security/1102", "System/104")
    linux = [
        e
        for e in events
        if e.source == "linux"
        and re.search(
            r"(rm|shred|truncate)\s.*(/var/log|\.bash_history)|history\s+-c", str(e.fields.get("command", ""))
        )
    ]
    findings = []
    if cleared:
        findings.append(
            Finding(
                rule="log_clearing",
                title="Windows event log cleared",
                severity="high",
                techniques=["T1070.001"],
                description=f"{len(cleared)} log clear event(s).",
                evidence=cleared,
                indicators={"user": sorted({e.user for e in cleared if e.user})},
            )
        )
    if linux:
        findings.append(
            Finding(
                rule="log_clearing",
                title="Linux logs or history wiped",
                severity="high",
                techniques=["T1070.002"],
                description=str(linux[0].fields.get("command")),
                evidence=linux,
            )
        )
    return findings


# --------------------------------------------------------------------------- network


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


@rule
def beaconing(events: list[Event]) -> list[Finding]:
    """Regular connections (low jitter) from one host to one destination."""
    conns = _of_type(events, "zeek/conn", "Sysmon/3")
    pairs: dict[tuple[str, str, int | None], list[Event]] = defaultdict(list)
    for e in conns:
        if e.src_ip and e.dst_ip and e.timestamp:
            pairs[(e.src_ip, e.dst_ip, e.dst_port)].append(e)
    findings = []
    for (src, dst, port), group in pairs.items():
        if len(group) < 8:
            continue
        stamps = sorted(e.timestamp for e in group)
        deltas = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:], strict=False)]
        mean = statistics.mean(deltas)
        if mean <= 0:
            continue
        jitter = statistics.pstdev(deltas) / mean
        if jitter < 0.2:
            findings.append(
                Finding(
                    rule="beaconing",
                    title=f"Periodic beaconing {src} -> {dst}:{port}",
                    severity="high",
                    techniques=["T1071.001" if port in (80, 443, 8080, 8443) else "T1573"],
                    description=f"{len(group)} connections, mean interval {mean:.0f}s, jitter {jitter:.2f}.",
                    evidence=group[:5],
                    indicators={"ip": [dst], "host_ip": [src]},
                )
            )
    return findings


@rule
def dns_tunneling(events: list[Event]) -> list[Finding]:
    queries = _of_type(events, "zeek/dns")
    by_domain: dict[str, list[Event]] = defaultdict(list)
    for e in queries:
        q = str(e.fields.get("query") or "")
        labels = q.split(".")
        if len(labels) < 3:
            continue
        base = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        if len(sub) > 30 and _entropy(sub) > 3.5:
            by_domain[base].append(e)
    findings = []
    for domain, hits in by_domain.items():
        if len(hits) < 5:
            continue
        findings.append(
            Finding(
                rule="dns_tunneling",
                title=f"Possible DNS tunneling / exfiltration via {domain}",
                severity="high",
                techniques=["T1071.004", "T1048"],
                description=f"{len(hits)} long high-entropy subdomain queries (e.g. {hits[0].fields.get('query')}).",
                evidence=hits[:5],
                indicators={"domain": [domain], "host_ip": sorted({e.src_ip for e in hits if e.src_ip})},
            )
        )
    return findings


@rule
def staging_files(events: list[Event]) -> list[Finding]:
    hits = [
        e
        for e in events
        if e.source == "timeline"
        and e.fields.get("suspicious_dir")
        and re.search(r"\.(exe|dll|ps1|bat|sh|elf|so|py)$|/[^/.]+$", str(e.fields.get("path", "")), re.I)
        and "b" in str(e.fields.get("macb", ""))
    ]
    if not hits:
        return []
    return [
        Finding(
            rule="staging_files",
            title="Executable files created in staging directories",
            severity="medium",
            techniques=["T1105"],
            description=", ".join(sorted({str(e.fields["path"]) for e in hits})[:6]),
            evidence=hits[:8],
            indicators={"file": sorted({str(e.fields["path"]) for e in hits})},
        )
    ]


# --------------------------------------------------------------------------- memory (Volatility 3)

SHELLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}
DOCUMENT_APPS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "acrord32.exe",
    "acrobat.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
}
# Expected parent of core Windows processes (Windows 10/11). Only checked when the parent is still
# in the process list: wininit.exe and csrss.exe are started by an smss.exe instance that exits.
EXPECTED_PARENT = {
    "svchost.exe": "services.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "lsaiso.exe": "wininit.exe",
    "taskhostw.exe": "svchost.exe",
}
CORE_NAMES = set(EXPECTED_PARENT) | {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "explorer.exe"}
SINGLETONS = {"lsass.exe", "services.exe", "wininit.exe"}
LOLBIN_TECHNIQUE = {"rundll32.exe": "T1218.011", "regsvr32.exe": "T1218.010", "mshta.exe": "T1218.005"}


def _edit_distance_1(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insertion, deletion, substitution or swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def _shell_technique(name: str) -> str:
    if name in ("powershell.exe", "pwsh.exe"):
        return "T1059.001"
    if name == "cmd.exe":
        return "T1059.003"
    return LOLBIN_TECHNIQUE.get(name, "T1059")


@rule
def memory_code_injection(events: list[Event]) -> list[Finding]:
    """Executable and writable private memory found by malfind: shellcode or an injected PE.

    RWX regions also exist in legitimate JIT runtimes (browsers, .NET), so only a region that starts
    with an MZ header is rated high.
    """
    hits = [
        e
        for e in _of_type(events, "memory/malfind")
        if "EXECUTE_READWRITE" in str(e.fields.get("protection", "")).upper()
    ]
    if not hits:
        return []
    with_pe = [e for e in hits if e.fields.get("mz_header")]
    procs = sorted({f"{e.process} ({e.fields.get('pid')})" for e in hits})
    desc = f"{len(hits)} executable and writable memory region(s) in {', '.join(procs[:5])}."
    if with_pe:
        desc += (
            f" {len(with_pe)} start with an MZ header: a whole executable was loaded without a file on disk."
        )
    return [
        Finding(
            rule="memory_code_injection",
            title="Code injected in process memory",
            severity="high" if with_pe else "medium",
            techniques=["T1055"],
            description=desc,
            evidence=(with_pe or hits)[:6],
            indicators={"process": sorted({str(e.process) for e in hits})},
        )
    ]


@rule
def memory_process_tree(events: list[Event]) -> list[Finding]:
    """Abnormal parent/child relations and look-alike names in the process list."""
    procs = _of_type(events, "memory/process")
    if not procs:
        return []
    by_pid = {e.fields.get("pid"): e for e in procs}
    findings = []

    spawned = []
    for e in procs:
        parent = by_pid.get(e.fields.get("ppid"))
        child, pname = str(e.process or "").lower(), str(parent.process if parent else "").lower()
        if parent and pname in DOCUMENT_APPS and child in SHELLS:
            spawned.append((parent, e))
    if spawned:
        techniques = {"T1204.002"} | {_shell_technique(str(c.process).lower()) for _, c in spawned}
        findings.append(
            Finding(
                rule="memory_process_tree",
                title="Document or browser process spawned a shell",
                severity="high",
                techniques=sorted(techniques),
                description="; ".join(
                    f"{p.process} ({p.fields.get('pid')}) -> {c.process} ({c.fields.get('pid')})"
                    for p, c in spawned[:5]
                ),
                evidence=[x for pair in spawned[:4] for x in pair],
                indicators={"process": sorted({str(c.process) for _, c in spawned})},
            )
        )

    masquerade = []
    for e in procs:
        name = str(e.process or "").lower()
        parent = by_pid.get(e.fields.get("ppid"))
        expected = EXPECTED_PARENT.get(name)
        if expected and parent and str(parent.process).lower() != expected:
            masquerade.append(
                (e, f"{e.process} ({e.fields.get('pid')}) started by {parent.process}, expected {expected}")
            )
        elif name not in CORE_NAMES and any(_edit_distance_1(name, core) for core in CORE_NAMES):
            masquerade.append((e, f"{e.process} ({e.fields.get('pid')}) imitates a Windows process name"))
    counts = Counter(str(e.process or "").lower() for e in procs if not e.fields.get("exit_time"))
    for name in SINGLETONS:
        if counts[name] > 1:
            dupes = [e for e in procs if str(e.process).lower() == name]
            masquerade.append((dupes[-1], f"{counts[name]} running {name} processes, only one is expected"))
    if masquerade:
        findings.append(
            Finding(
                rule="memory_process_tree",
                title="Process masquerading as a Windows system process",
                severity="high",
                techniques=["T1036.005"],
                description="; ".join(text for _, text in masquerade[:5]),
                evidence=[e for e, _ in masquerade[:6]],
                indicators={"process": sorted({str(e.process) for e, _ in masquerade})},
            )
        )
    return findings


@rule
def memory_suspicious_connection(events: list[Event]) -> list[Finding]:
    """Shells and proxy binaries holding a connection to a public address (reverse shell, C2, download)."""
    hits = []
    for e in _of_type(events, "memory/netconn"):
        if str(e.process or "").lower() not in SHELLS or not e.dst_ip or not e.dst_port:
            continue
        try:
            ip = ipaddress.ip_address(_norm_ip(e.dst_ip))
        except ValueError:
            continue
        # Same definition of "internal" as the privacy layer (is_global would also exclude TEST-NET).
        if not (ip.is_loopback or ip.is_unspecified or any(ip in net for net in INTERNAL_NETS)):
            hits.append(e)
    if not hits:
        return []
    techniques = {_shell_technique(str(e.process).lower()) for e in hits}
    techniques |= {"T1071.001" if e.dst_port in (80, 443, 8080, 8443) else "T1095" for e in hits}
    return [
        Finding(
            rule="memory_suspicious_connection",
            title="Shell or proxy binary connected to an external host",
            severity="high",
            techniques=sorted(techniques),
            description="; ".join(
                f"{e.process} ({e.fields.get('pid')}) -> {e.dst_ip}:{e.dst_port} {e.fields.get('state') or ''}".strip()
                for e in hits[:5]
            ),
            evidence=hits[:6],
            indicators={
                "ip": sorted({str(e.dst_ip) for e in hits}),
                "process": sorted({str(e.process) for e in hits}),
            },
        )
    ]


def run_all(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        findings.extend(r(events))
    # Memory findings can have no timestamp at all (malfind, cmdline): sort those last.
    findings.sort(
        key=lambda f: (
            -SEVERITY_ORDER[f.severity],
            f.first_seen is None,
            f.first_seen.timestamp() if f.first_seen else 0,
        )
    )
    return findings
