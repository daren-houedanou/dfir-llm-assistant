"""Windows Event Log records as produced by ``evtx_dump`` (omerbenamram/evtx).

nix-forensics ships this tool as ``evtxTools``. The expected input is the
output of ``evtx_dump -o jsonl Security.evtx`` (one JSON record per line) or
``evtx_dump -o json`` (concatenated pretty-printed records).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import Event
from .common import parse_ts

# EventData fields that map onto the normalized schema, in priority order.
USER_FIELDS = ("TargetUserName", "SubjectUserName", "User", "AccountName")
SRC_IP_FIELDS = ("IpAddress", "SourceAddress", "SourceIp", "ClientAddress")
DST_IP_FIELDS = ("DestAddress", "DestinationIp")
PROCESS_FIELDS = ("NewProcessName", "ProcessName", "Image", "ImagePath", "Application")

EMPTY_VALUES = {"", "-", "::1", "127.0.0.1", "N/A", None}

# Short human labels make the LLM context far more useful than bare IDs.
EVENT_LABELS = {
    ("Security", 4624): "logon success",
    ("Security", 4625): "logon failure",
    ("Security", 4634): "logoff",
    ("Security", 4648): "explicit credentials logon",
    ("Security", 4672): "special privileges assigned",
    ("Security", 4688): "process created",
    ("Security", 4698): "scheduled task created",
    ("Security", 4720): "user account created",
    ("Security", 4741): "computer account created",
    ("Security", 4768): "kerberos TGT request",
    ("Security", 4771): "kerberos pre-authentication failed",
    ("Security", 4722): "user account enabled",
    ("Security", 4724): "password reset attempt",
    ("Security", 4728): "member added to global group",
    ("Security", 4732): "member added to local group",
    ("Security", 4756): "member added to universal group",
    ("Security", 1102): "audit log cleared",
    ("System", 7045): "service installed",
    ("System", 104): "event log cleared",
    ("Microsoft-Windows-PowerShell/Operational", 4104): "powershell script block",
    ("Microsoft-Windows-Sysmon/Operational", 1): "sysmon process create",
    ("Microsoft-Windows-Sysmon/Operational", 3): "sysmon network connection",
}


def _short_channel(channel: str) -> str:
    if channel.startswith("Microsoft-Windows-Sysmon"):
        return "Sysmon"
    if channel.startswith("Microsoft-Windows-PowerShell"):
        return "PowerShell"
    return channel


def _first(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if value not in EMPTY_VALUES:
            return str(value)
    return None


def _event_data(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("EventData") or event.get("UserData") or {}
    if not isinstance(raw, dict):
        return {"Data": raw}
    # UserData is usually nested one level deeper (e.g. {"LogFileCleared": {...}}).
    if len(raw) == 1 and isinstance(next(iter(raw.values())), dict) and "#attributes" not in raw:
        inner = next(iter(raw.values()))
        return {k: v for k, v in inner.items() if k != "#attributes"}
    return {k: v for k, v in raw.items() if k != "#attributes"}


def record_to_event(record: dict[str, Any], artifact: str, ref: int) -> Event:
    event = record.get("Event", record)
    system = event.get("System", {})
    channel = system.get("Channel", "Unknown")
    event_id_raw = system.get("EventID")
    if isinstance(event_id_raw, dict):  # {"#text": 4625, "#attributes": {...}}
        event_id_raw = event_id_raw.get("#text")
    event_id = int(event_id_raw) if event_id_raw is not None else -1
    ts = (system.get("TimeCreated") or {}).get("#attributes", {}).get("SystemTime")
    data = _event_data(event)

    label = EVENT_LABELS.get((channel, event_id), "")
    user = _first(data, USER_FIELDS)
    if event_id in (4728, 4732, 4756):  # group membership: TargetUserName is the *group*
        user = _first(data, ("MemberName", "MemberSid", "SubjectUserName"))
    process = _first(data, PROCESS_FIELDS)
    message_bits = [label] if label else []
    for key in (
        "LogonType",
        "ServiceName",
        "TaskName",
        "MemberName",
        "TargetUserName",
        "CommandLine",
        "ScriptBlockText",
        "Status",
        "SubStatus",
    ):
        if key in data and data[key] not in EMPTY_VALUES:
            value = str(data[key]).replace("\n", " ")
            message_bits.append(f"{key}={value[:160]}")

    dst_port = data.get("DestinationPort") or data.get("DestPort")
    return Event(
        timestamp=parse_ts(ts),
        source="evtx",
        event_type=f"{_short_channel(channel)}/{event_id}",
        host=system.get("Computer"),
        user=user,
        src_ip=_first(data, SRC_IP_FIELDS),
        dst_ip=_first(data, DST_IP_FIELDS),
        dst_port=int(dst_port) if str(dst_port or "").isdigit() else None,
        process=process,
        message=" ".join(message_bits),
        fields={"channel": channel, "event_id": event_id, **data},
        artifact=artifact,
        ref=ref,
    )


def _iter_json_objects(text: str) -> Iterator[dict[str, Any]]:
    """Handle both JSONL and ``evtx_dump -o json`` output (which prefixes records with 'Record N')."""
    decoder = json.JSONDecoder()
    idx, length = 0, len(text)
    while idx < length:
        brace = text.find("{", idx)
        if brace == -1:
            return
        obj, end = decoder.raw_decode(text, brace)
        idx = end
        if isinstance(obj, dict):
            yield obj


def parse(path: Path) -> Iterator[Event]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for ref, record in enumerate(_iter_json_objects(text)):
        yield record_to_event(record, str(path), ref)


def parse_binary(path: Path) -> Iterator[Event]:
    """Parse a raw .evtx file by shelling out to ``evtx_dump`` (packaged by nix-forensics as evtxTools)."""
    exe = shutil.which("evtx_dump")
    if not exe:
        raise RuntimeError(
            f"{path}: raw .evtx needs `evtx_dump` on PATH (available in the nix-forensics shell or "
            "`nix develop` of this repo). Alternatively convert first: evtx_dump -o jsonl FILE > FILE.jsonl"
        )
    proc = subprocess.run([exe, "-o", "jsonl", str(path)], capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"evtx_dump failed on {path}: {proc.stderr.strip()[:300]}")
    for ref, record in enumerate(_iter_json_objects(proc.stdout)):
        yield record_to_event(record, str(path), ref)


def sniff(path: Path, head: str) -> bool:
    start = head.lstrip()
    if not (start.startswith("{") or start.startswith("Record ")):
        return False
    return ('"Event"' in head and '"System"' in head) or ('"EventID"' in head and '"Channel"' in head)
