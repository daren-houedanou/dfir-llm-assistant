"""Filesystem timelines.

* ``bodyfile`` (mactime format) as written by ``usnrs-cli -f bodyfile``, ``fls -m`` or ``timeliner``
  in nix-forensics: ``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime``.
* Plaso ``psort.py -o l2tcsv`` CSV output.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from ..models import Event
from .common import parse_ts

L2T_HEADER = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc"
SUSPICIOUS_DIRS = (
    "/tmp/",
    "/dev/shm/",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\tasks\\",
    "\\perflogs\\",
)


def _bodyfile(path: Path) -> Iterator[Event]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for ref, line in enumerate(handle):
            cols = line.rstrip("\n").split("|")
            if len(cols) < 11:
                continue
            name = cols[1]
            stamps = {"m": cols[8], "a": cols[7], "c": cols[9], "b": cols[10]}
            # Emit one event per distinct timestamp, labeled with its MACB flags.
            grouped: dict[str, str] = {}
            for flag, value in stamps.items():
                if value and value not in ("0", "-1"):
                    grouped.setdefault(value, "")
                    grouped[value] += flag
            for value, flags in grouped.items():
                macb = "".join(f if f in flags else "." for f in "macb")
                yield Event(
                    timestamp=parse_ts(value),
                    source="timeline",
                    event_type=f"fs/{macb}",
                    user=cols[4] if cols[4] not in ("", "0") else None,
                    process=None,
                    message=f"{name} size={cols[6]}",
                    fields={
                        "path": name,
                        "inode": cols[2],
                        "mode": cols[3],
                        "size": cols[6],
                        "macb": macb,
                        "suspicious_dir": any(d in name.lower() for d in SUSPICIOUS_DIRS),
                    },
                    artifact=str(path),
                    ref=ref,
                )


def _l2tcsv(path: Path) -> Iterator[Event]:
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for ref, row in enumerate(csv.DictReader(handle)):
            ts = parse_ts(f"{row.get('date', '')} {row.get('time', '')}")
            desc = row.get("desc") or row.get("short") or ""
            yield Event(
                timestamp=ts,
                source="timeline",
                event_type=f"plaso/{row.get('source', '?')}",
                host=row.get("host") or None,
                user=row.get("user") if row.get("user") not in ("", "-") else None,
                message=f"[{row.get('MACB', '')}] {row.get('sourcetype', '')}: {desc}"[:220],
                fields=dict(row),
                artifact=str(path),
                ref=ref,
            )


def parse(path: Path) -> Iterator[Event]:
    head = path.open(encoding="utf-8", errors="replace").readline()
    if head.lower().startswith("date,time"):
        yield from _l2tcsv(path)
    else:
        yield from _bodyfile(path)


def sniff(path: Path, head: str) -> bool:
    first = head.splitlines()[0] if head else ""
    return first.lower().startswith("date,time") or first.count("|") == 10
