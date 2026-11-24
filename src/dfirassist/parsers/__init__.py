"""Artifact parsers with format auto-detection.

Each parser module exposes ``parse(path) -> Iterator[Event]`` and ``sniff(path, head) -> bool``.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from ..models import Event
from . import evtx, linux, memory, timeline, zeek

PARSERS = {
    "evtx": evtx,
    "memory": memory,
    "zeek": zeek,
    "timeline": timeline,
    "linux": linux,
}


# Files commonly found next to artifacts that are never artifacts themselves.
IGNORED_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".txt", ".gz", ".zip"}


class UnknownFormatError(ValueError):
    pass


def detect_format(path: Path) -> str:
    if path.suffix.lower() == ".evtx":
        return "evtx-binary"
    with path.open(encoding="utf-8", errors="replace") as handle:
        head = handle.read(4096)
    for name, module in PARSERS.items():
        if module.sniff(path, head):
            return name
    raise UnknownFormatError(
        f"{path}: unknown format. Supported: evtx_dump JSON/JSONL, Linux auth/syslog, "
        "bodyfile, Plaso l2tcsv, Zeek TSV/JSON, Volatility 3 JSON. Force one with --format."
    )


def parse_file(path: Path, fmt: str | None = None) -> Iterator[Event]:
    fmt = fmt or detect_format(path)
    if fmt == "evtx-binary":
        yield from evtx.parse_binary(path)
        return
    if fmt not in PARSERS:
        raise UnknownFormatError(f"unsupported format {fmt!r}; choose from {', '.join(PARSERS)}")
    yield from PARSERS[fmt].parse(path)


def load(paths: Iterable[Path], fmt: str | None = None) -> list[Event]:
    """Parse every artifact and return a single, time-ordered event list."""
    events: list[Event] = []
    for path in paths:
        if path.is_dir():
            files = sorted(
                p
                for p in path.rglob("*")
                if p.is_file() and not p.name.startswith(".") and p.suffix not in IGNORED_SUFFIXES
            )
        else:
            files = [path]
        for file in files:
            events.extend(parse_file(file, fmt))
    events.sort(key=lambda e: (e.timestamp is None, e.timestamp or 0, e.artifact, e.ref))
    return events
