"""Forensic audit trail for every model interaction.

An LLM is an *analytic aid*, never evidence. What must hold up later (peer review,
report, court) is the chain: original artifacts -> deterministic tooling -> analyst
conclusions. The audit log makes the LLM's part of that chain inspectable and
re-playable:

* the SHA-256 of every input artifact;
* the exact request (system prompt, history, user prompt as sent, after pseudonymization),
  the model alias, the model that actually served it, and the sampling parameters
  (temperature 0, fixed seed);
* the raw response and its SHA-256;
* tool and prompt versions;
* a hash chain (``prev_hash`` -> ``record_hash``) so that any edit, insertion or deletion
  of a record is detectable (``dfa audit verify``).

``dfa audit replay`` re-sends the recorded requests and reports whether the answers are
byte-identical. Temperature 0 + seed makes local models (Ollama, llama.cpp) reproducible
on the same model build and hardware in practice; hosted APIs do not guarantee it, which
is one more reason why the conclusions must rest on the deterministic findings.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__

GENESIS = "0" * 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def hash_inputs(paths: list[Path]) -> list[dict[str, Any]]:
    files: list[Path] = []
    for p in paths:
        files.extend(sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p])
    return [{"path": str(f), "sha256": sha256_file(f), "size": f.stat().st_size} for f in files]


@dataclass
class AuditLog:
    path: Path
    case_id: str = field(default_factory=lambda: os.environ.get("DFA_CASE_ID", ""))
    inputs: list[dict[str, Any]] = field(default_factory=list)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line)["record_hash"]
        return last

    def set_inputs(self, paths: list[Path]) -> None:
        self.inputs = hash_inputs(paths)

    def record(
        self,
        *,
        operation: str,
        model_alias: str,
        served_model: str,
        params: dict[str, Any],
        messages: list[dict[str, str]],
        response: str,
        meta: dict[str, Any] | None = None,
        pseudonymized: bool = False,
        prompt_version: str = "",
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": f"dfir-llm-assistant {__version__}",
            "prompt_version": prompt_version,
            "case_id": self.case_id,
            "operation": operation,
            "inputs": self.inputs,
            "model_alias": model_alias,
            "served_model": served_model,
            "params": params,
            "pseudonymized": pseudonymized,
            "request": messages,
            "request_sha256": sha256_text(_canonical(messages)),
            "response": response,
            "response_sha256": sha256_text(response),
            "meta": meta or {},
            "prev_hash": self._last_hash(),
        }
        entry["record_hash"] = sha256_text(_canonical(entry))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry


def read(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


@dataclass
class VerifyResult:
    records: int
    chain_ok: bool
    broken_at: int | None
    input_mismatches: list[str]


def verify(path: Path, check_inputs: bool = True) -> VerifyResult:
    """Check the hash chain and, optionally, that input artifacts still match their recorded hashes."""
    records = read(path)
    prev = GENESIS
    broken_at = None
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        if rec.get("prev_hash") != prev or sha256_text(_canonical(body)) != rec.get("record_hash"):
            broken_at = i
            break
        prev = rec["record_hash"]
    mismatches: list[str] = []
    if check_inputs:
        seen: dict[str, str] = {}
        for rec in records:
            for item in rec.get("inputs", []):
                seen[item["path"]] = item["sha256"]
        for file, digest in seen.items():
            p = Path(file)
            if not p.exists():
                mismatches.append(f"{file}: missing")
            elif sha256_file(p) != digest:
                mismatches.append(f"{file}: content changed")
    return VerifyResult(len(records), broken_at is None, broken_at, mismatches)
