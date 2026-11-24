"""Small offline subset of MITRE ATT&CK (Enterprise) used for mapping and for validating LLM output.

Kept local on purpose: the tool must work air-gapped. Extend with the full STIX bundle
(``enterprise-attack.json``) via :func:`load_stix` when it is available.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

TECHNIQUES: dict[str, tuple[str, str]] = {
    # id: (name, tactic)
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential-access"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1049": ("System Network Connections Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "lateral-movement"),
    "T1021.004": ("Remote Services: SSH", "lateral-movement"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "execution"),
    "T1055": ("Process Injection", "defense-evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "defense-evasion"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "defense-evasion"),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", "defense-evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "defense-evasion"),
    "T1095": ("Non-Application Layer Protocol", "command-and-control"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "defense-evasion"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "defense-evasion"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1071.004": ("Application Layer Protocol: DNS", "command-and-control"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1110.001": ("Brute Force: Password Guessing", "credential-access"),
    "T1110.003": ("Brute Force: Password Spraying", "credential-access"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    "T1572": ("Protocol Tunneling", "command-and-control"),
    "T1573": ("Encrypted Channel", "command-and-control"),
}

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("unknown technique", ""))[0]


def extract_ids(text: str) -> set[str]:
    return set(TECHNIQUE_RE.findall(text or ""))


def is_known(technique_id: str) -> bool:
    return technique_id in TECHNIQUES or technique_id.split(".")[0] in {t.split(".")[0] for t in TECHNIQUES}


def load_stix(path: Path) -> int:
    """Merge techniques from an ATT&CK STIX bundle; returns the number of techniques loaded."""
    bundle = json.loads(path.read_text())
    count = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None
        )
        if not ext:
            continue
        phases = obj.get("kill_chain_phases") or [{}]
        TECHNIQUES[ext["external_id"]] = (obj.get("name", ""), phases[0].get("phase_name", ""))
        count += 1
    return count
