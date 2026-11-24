"""Linux authentication and system logs (auth.log / secure / syslog, RFC3164 or ISO timestamps)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ..models import Event
from .common import parse_ts

LINE_RE = re.compile(
    r"^(?P<ts>(?:\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\S+))\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# (event_type, programs, regex), evaluated in order. Named groups feed the normalized fields.
SSHD = {"sshd"}
PATTERNS: list[tuple[str, set[str], re.Pattern[str]]] = [
    (
        "sshd/failed_password",
        SSHD,
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
    ),
    ("sshd/invalid_user", SSHD, re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+)")),
    (
        "sshd/accepted",
        SSHD,
        re.compile(
            r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<src_ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
    ),
    (
        "sudo/command",
        {"sudo"},
        re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.+)$"),
    ),
    ("useradd/new_user", {"useradd", "adduser"}, re.compile(r"new user: name=(?P<user>[^,]+),")),
    (
        "usermod/group_add",
        {"usermod", "gpasswd"},
        re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
    ),
    ("passwd/changed", {"passwd", "chpasswd"}, re.compile(r"password changed for (?P<user>\S+)")),
    (
        "cron/edit",
        {"crontab"},
        re.compile(r"\((?P<user>[^)]+)\) (?:REPLACE|BEGIN EDIT|END EDIT) \((?P<target>[^)]+)\)"),
    ),
    ("cron/cmd", {"CRON", "cron", "crond"}, re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<command>.+)\)$")),
    (
        "session/opened",
        {"sshd", "sudo", "su", "login", "CRON", "systemd-logind"},
        re.compile(r"session opened for user (?P<user>[^\s(]+)"),
    ),
    ("systemd/service", {"systemd"}, re.compile(r"(?:Started|Starting) (?P<command>.+?)\.?$")),
]


def classify(prog: str, msg: str) -> tuple[str, dict[str, str]]:
    for event_type, programs, pattern in PATTERNS:
        if prog in programs:
            found = pattern.search(msg)
            if found:
                return event_type, {k: v for k, v in found.groupdict().items() if v is not None}
    return f"{prog}/other", {}


def parse(path: Path, default_year: int | None = None) -> Iterator[Event]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for ref, raw in enumerate(handle):
            match = LINE_RE.match(raw.rstrip("\n"))
            if not match:
                continue
            prog = match["prog"].split("/")[-1]
            msg = match["msg"]
            event_type, groups = classify(prog, msg)
            fields: dict[str, str | None] = {**groups, "program": prog, "pid": match["pid"]}
            yield Event(
                timestamp=parse_ts(match["ts"], default_year=default_year),
                source="linux",
                event_type=event_type,
                host=match["host"],
                user=groups.get("user"),
                src_ip=groups.get("src_ip"),
                dst_port=22 if prog == "sshd" and groups.get("src_ip") else None,
                process=groups.get("command") or prog,
                message=msg[:200],
                fields=fields,
                artifact=str(path),
                ref=ref,
            )


def sniff(path: Path, head: str) -> bool:
    first = head.splitlines()[0] if head else ""
    return bool(LINE_RE.match(first))
