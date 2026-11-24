"""Volatility 3 plugin output rendered as JSON (``vol -r json``) or JSON Lines (``vol -r jsonl``).

Volatility does not write the plugin name in its output, so the plugin is recognised from its
columns. Supported Windows plugins and the events they become:

=====================================  ======================  ==========================================
Plugin                                 Event type              Key fields
=====================================  ======================  ==========================================
``windows.pslist`` / ``windows.pstree``  ``memory/process``    PID, PPID, image name, creation time
``windows.cmdline``                    ``memory/cmdline``      full command line (``CommandLine`` field)
``windows.netscan`` / ``windows.netstat``  ``memory/netconn``  local and remote address, state, owner
``windows.malfind``                    ``memory/malfind``      protection, private memory, MZ header
=====================================  ======================  ==========================================

``pstree`` nests children under ``__children``: the tree is flattened, the parent is kept in PPID.
The command line is stored under ``CommandLine`` so the generic execution rules apply to it unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import Event
from .common import parse_ts

# Column sets that identify each plugin (a row must contain all of them).
SIGNATURES: list[tuple[str, set[str]]] = [
    ("malfind", {"PID", "Process", "Protection", "Hexdump"}),
    ("netconn", {"ForeignAddr", "ForeignPort", "LocalAddr", "Owner"}),
    ("cmdline", {"PID", "Process", "Args"}),
    ("process", {"PID", "PPID", "ImageFileName"}),
]
MARKERS = ('"ImageFileName"', '"ForeignAddr"', '"Args"', '"Protection"')


def _plugin(row: dict[str, Any]) -> str | None:
    for name, columns in SIGNATURES:
        if columns <= row.keys():
            return name
    return None


def _flatten(rows: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for row in rows:
        yield row
        yield from _flatten(row.get("__children") or [])


def _rows(path: Path) -> Iterator[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if text.startswith("["):
        yield from _flatten(json.loads(text))
        return
    for line in text.splitlines():  # JSON Lines renderer: one top-level row per line
        if line.strip().startswith("{"):
            yield from _flatten([json.loads(line)])


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_mz(hexdump: str | None) -> bool:
    """True when the region starts with an MZ header, i.e. a whole PE image sits in that memory."""
    first = (hexdump or "").split()[:2]
    return [b.lower() for b in first] == ["4d", "5a"]


def parse(path: Path) -> Iterator[Event]:
    for ref, row in enumerate(_rows(path)):
        plugin = _plugin(row)
        pid = _int(row.get("PID"))
        if plugin == "process":
            ppid = _int(row.get("PPID"))
            yield Event(
                timestamp=parse_ts(row.get("CreateTime")),
                source="memory",
                event_type="memory/process",
                process=row.get("ImageFileName"),
                message=f"pid={pid} ppid={ppid}" + (" exited" if row.get("ExitTime") else ""),
                fields={
                    "pid": pid,
                    "ppid": ppid,
                    "session": row.get("SessionId"),
                    "exit_time": row.get("ExitTime"),
                    "wow64": row.get("Wow64"),
                },
                artifact=str(path),
                ref=ref,
            )
        elif plugin == "cmdline":
            args = row.get("Args") or ""
            yield Event(
                timestamp=None,
                source="memory",
                event_type="memory/cmdline",
                process=row.get("Process"),
                message=f"pid={pid} {args}",
                fields={"pid": pid, "CommandLine": args},
                artifact=str(path),
                ref=ref,
            )
        elif plugin == "netconn":
            yield Event(
                timestamp=parse_ts(row.get("Created")),
                source="memory",
                event_type="memory/netconn",
                src_ip=row.get("LocalAddr"),
                dst_ip=row.get("ForeignAddr"),
                dst_port=_int(row.get("ForeignPort")),
                process=row.get("Owner"),
                message=f"pid={pid} {row.get('Proto')} {row.get('State') or ''}".strip(),
                fields={
                    "pid": pid,
                    "proto": row.get("Proto"),
                    "state": row.get("State"),
                    "local_port": _int(row.get("LocalPort")),
                },
                artifact=str(path),
                ref=ref,
            )
        elif plugin == "malfind":
            mz = _is_mz(row.get("Hexdump"))
            yield Event(
                timestamp=None,
                source="memory",
                event_type="memory/malfind",
                process=row.get("Process"),
                message=f"pid={pid} {row.get('Protection')} at {row.get('Start VPN')}"
                + (" MZ header" if mz else ""),
                fields={
                    "pid": pid,
                    "protection": row.get("Protection"),
                    "private": bool(row.get("PrivateMemory")),
                    "start": row.get("Start VPN"),
                    "tag": row.get("Tag"),
                    "mz_header": mz,
                },
                artifact=str(path),
                ref=ref,
            )


def sniff(path: Path, head: str) -> bool:
    start = head.lstrip()
    # Rows are written with sorted keys and malfind rows carry long hexdumps, so "__children" may
    # fall outside the first 4 KB: rely on the plugin columns instead.
    return start[:1] in "[{" and '"PID"' in head and any(m in head for m in MARKERS)
