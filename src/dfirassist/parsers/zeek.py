"""Zeek logs (conn, dns, http, ssl) in either the default TSV format or JSON (``LogAscii::use_json``)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import Event
from .common import parse_ts


def _iter_rows(path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    log_path = path.stem.split(".")[0]
    fields: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#path"):
                    log_path = line.split("\t", 1)[1]
                elif line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                continue
            if line.startswith("{"):
                yield log_path, json.loads(line)
            elif fields:
                values = line.split("\t")
                yield (
                    log_path,
                    {k: (None if v in ("-", "(empty)") else v) for k, v in zip(fields, values, strict=False)},
                )


def parse(path: Path) -> Iterator[Event]:
    for ref, (log, row) in enumerate(_iter_rows(path)):
        message_bits = []
        if log == "dns":
            message_bits.append(
                f"query={row.get('query')} qtype={row.get('qtype_name')} rcode={row.get('rcode_name')}"
            )
        elif log == "http":
            message_bits.append(
                f"{row.get('method')} {row.get('host')}{row.get('uri')} ua={row.get('user_agent')}"
            )
        elif log == "ssl":
            message_bits.append(f"sni={row.get('server_name')} ja3={row.get('ja3', '-')}")
        else:
            message_bits.append(
                f"proto={row.get('proto')} service={row.get('service')} dur={row.get('duration')} "
                f"out={row.get('orig_bytes')} in={row.get('resp_bytes')} state={row.get('conn_state')}"
            )
        port = row.get("id.resp_p")
        yield Event(
            timestamp=parse_ts(row.get("ts")),
            source="zeek",
            event_type=f"zeek/{log}",
            src_ip=row.get("id.orig_h"),
            dst_ip=row.get("id.resp_h"),
            dst_port=int(port) if port not in (None, "") else None,
            message=" ".join(message_bits),
            fields=row,
            artifact=str(path),
            ref=ref,
        )


def sniff(path: Path, head: str) -> bool:
    return head.startswith("#separator") or ('"id.orig_h"' in head and '"ts"' in head)
