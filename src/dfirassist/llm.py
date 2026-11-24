"""Client side of the LLM gateway.

All model traffic goes through a LiteLLM proxy (OpenAI-compatible API). The client
never talks to a provider directly, so routing, keys, budgets and audit logs stay
centralised in the gateway (see ``deploy/``).

On top of the gateway the client enforces a *data-handling policy*:

* ``confidential`` (default): only model aliases declared local are allowed;
  the request is refused before any byte leaves the machine otherwise.
* ``cloud`` (explicit opt-in): a cloud alias may be used, and the prompt is
  always pseudonymized first, then the answer is rehydrated locally.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .audit import AuditLog
from .privacy import Pseudonymizer
from .prompts import PROMPT_VERSION


class PolicyError(RuntimeError):
    pass


class GatewayError(RuntimeError):
    pass


@dataclass
class Settings:
    gateway_url: str = field(
        default_factory=lambda: os.environ.get("DFA_GATEWAY_URL", "http://localhost:4000")
    )
    api_key: str = field(
        default_factory=lambda: os.environ.get("DFA_API_KEY", os.environ.get("LITELLM_MASTER_KEY", ""))
    )
    backend: str = field(default_factory=lambda: os.environ.get("DFA_BACKEND", "litellm"))  # litellm | mock
    local_model: str = field(default_factory=lambda: os.environ.get("DFA_LOCAL_MODEL", "dfir-local"))
    cloud_model: str = field(default_factory=lambda: os.environ.get("DFA_CLOUD_MODEL", "dfir-cloud"))
    local_models: set[str] = field(
        default_factory=lambda: set(
            os.environ.get("DFA_LOCAL_MODELS", "dfir-local,dfir-local-small,dfir-local-large").split(",")
        )
    )
    timeout: float = field(default_factory=lambda: float(os.environ.get("DFA_TIMEOUT", "300")))
    # Fixed sampling for reproducibility: greedy decoding and a constant seed.
    temperature: float = 0.0
    seed: int = field(default_factory=lambda: int(os.environ.get("DFA_SEED", "42")))


@dataclass
class Completion:
    text: str
    model: str
    latency_s: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    pseudonymized: bool = False
    sent_prompt: str = ""  # exactly what left the client (for audit / leak tests)


class Backend(Protocol):
    def chat(self, model: str, messages: list[dict[str, str]], json_mode: bool) -> tuple[str, dict, str]: ...


class LiteLLMBackend:
    def __init__(self, settings: Settings):
        self.settings = settings
        headers = {"Authorization": f"Bearer {settings.api_key}"} if settings.api_key else {}
        self.client = httpx.Client(
            base_url=settings.gateway_url.rstrip("/"), headers=headers, timeout=settings.timeout
        )

    def chat(self, model: str, messages: list[dict[str, str]], json_mode: bool) -> tuple[str, dict, str]:
        payload: dict = {
            "model": model,
            "messages": messages,
            "temperature": self.settings.temperature,
            "seed": self.settings.seed,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            resp = self.client.post("/v1/chat/completions", json=payload)
        except httpx.HTTPError as exc:
            raise GatewayError(f"cannot reach LLM gateway at {self.settings.gateway_url}: {exc}") from exc
        if resp.status_code >= 400:
            raise GatewayError(f"gateway returned {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        self.last_meta = {
            "response_id": data.get("id"),
            "system_fingerprint": data.get("system_fingerprint"),
            "finish_reason": (data.get("choices") or [{}])[0].get("finish_reason"),
        }
        return data["choices"][0]["message"]["content"] or "", data.get("usage", {}), data.get("model", model)

    def models(self) -> list[str]:
        resp = self.client.get("/v1/models")
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("data", [])]


class MockBackend:
    """Deterministic offline backend.

    It echoes the deterministic findings in the expected output format. Used for tests,
    demos without a GPU, and as the *rules-only baseline* in the evaluation harness.
    """

    def chat(self, model: str, messages: list[dict[str, str]], json_mode: bool) -> tuple[str, dict, str]:
        prompt = messages[-1]["content"]
        findings = re.findall(r"^\[F\d+\] (\w+) (.+?) \| (.+)$", prompt, re.M)
        if "Write a " in prompt and "query" in prompt:
            return _mock_query(prompt), {}, "mock"
        techniques, seen = [], set()
        for _sev, _title, techs in findings:
            for tid, tname in re.findall(r"(T\d{4}(?:\.\d{3})?) ([^,]+)", techs):
                if tid not in seen:
                    seen.add(tid)
                    techniques.append({"id": tid, "name": tname.strip(), "evidence": _title})
        iocs, seen_iocs = [], set()
        for line in re.findall(r"^\s+indicators: (.+)$", prompt, re.M):
            for kind, values in re.findall(r"(\w+)=([^;]+)", line):
                for value in values.split(","):
                    if value.strip() and value not in seen_iocs:
                        seen_iocs.add(value)
                        iocs.append({"type": kind, "value": value.strip()})
        top = findings[0][1] if findings else "no deterministic finding"
        verdict = (
            "malicious"
            if any(s in ("CRITICAL", "HIGH") for s, _, _ in findings)
            else ("suspicious" if findings else "benign")
        )
        if "Question:" in prompt:
            question = prompt.split("Question:", 1)[1].split("\n", 1)[0].strip()
            body = (
                "\n".join(f"- [F{i}] {s} {t}" for i, (s, t, _) in enumerate(findings, 1))
                or "- nothing detected"
            )
            return (
                f"(mock backend) Question: {question}\nRelevant deterministic findings:\n{body}",
                {},
                "mock",
            )
        report = {
            "summary": f"Rules-only baseline: {len(findings)} finding(s); most severe: {top}.",
            "verdict": verdict,
            "confidence": "medium" if findings else "low",
            "timeline": [],
            "techniques": techniques,
            "iocs": iocs,
            "next_steps": ["Validate findings with a local LLM run", "Collect memory image (volatility3)"],
        }
        return json.dumps(report), {}, "mock"


def _mock_query(prompt: str) -> str:
    if "Sigma" in prompt:
        return (
            "```yaml\ntitle: Mock rule\nid: 00000000-0000-4000-8000-000000000000\nstatus: experimental\n"
            "logsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n"
            "  condition: selection\nlevel: medium\ntags:\n  - attack.t1110.001\n```\nMock Sigma rule."
        )
    if "jq" in prompt:
        return "```\nselect(.Event.System.EventID == 4625) | .Event.EventData.IpAddress\n```\nMock jq filter."
    return "```\nindex=wineventlog EventCode=4625 | stats count by Source_Network_Address\n```\nMock query."


class LLMClient:
    def __init__(
        self, settings: Settings | None = None, backend: Backend | None = None, audit: AuditLog | None = None
    ):
        self.settings = settings or Settings()
        self.audit = audit
        if backend is not None:
            self.backend = backend
        elif self.settings.backend == "mock":
            self.backend = MockBackend()
        else:
            self.backend = LiteLLMBackend(self.settings)

    def resolve(self, model: str | None, allow_cloud: bool) -> tuple[str, bool]:
        """Return (model alias, must_pseudonymize) according to the data-handling policy."""
        chosen = model or (self.settings.cloud_model if allow_cloud else self.settings.local_model)
        is_local = chosen in self.settings.local_models
        if not is_local and not allow_cloud:
            raise PolicyError(
                f"model '{chosen}' is not declared local and the case is confidential. "
                "Use a local alias or pass --cloud to explicitly allow pseudonymized cloud processing."
            )
        return chosen, not is_local

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        model: str | None = None,
        allow_cloud: bool = False,
        json_mode: bool = False,
        pseudonymizer: Pseudonymizer | None = None,
        history: list[dict[str, str]] | None = None,
        operation: str = "complete",
    ) -> Completion:
        alias, must_mask = self.resolve(model, allow_cloud)
        masker = pseudonymizer if must_mask else None
        if must_mask and masker is None:
            masker = Pseudonymizer()
        sent = masker.mask(prompt) if masker else prompt
        messages = [
            {"role": "system", "content": system},
            *(history or []),
            {"role": "user", "content": sent},
        ]
        start = time.perf_counter()
        text, usage, served = self.backend.chat(alias, messages, json_mode)
        latency = time.perf_counter() - start
        raw = text
        if masker:
            text = masker.unmask(text)
        if self.audit is not None:
            self.audit.record(
                operation=operation,
                model_alias=alias,
                served_model=served or alias,
                params={
                    "temperature": self.settings.temperature,
                    "seed": self.settings.seed,
                    "json_mode": json_mode,
                },
                messages=messages,
                response=raw,  # exactly what the model returned (pseudonymized if masking was applied)
                meta={**getattr(self.backend, "last_meta", {}), "latency_s": round(latency, 3)},
                pseudonymized=masker is not None,
                prompt_version=PROMPT_VERSION,
            )
        return Completion(
            text=text,
            model=served or alias,
            latency_s=latency,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            pseudonymized=masker is not None,
            sent_prompt=sent,
        )

    def replay(self, record: dict) -> str:
        """Re-send a recorded request unchanged and return the raw answer (see ``dfa audit replay``)."""
        text, _, _ = self.backend.chat(
            record["model_alias"], record["request"], record["params"].get("json_mode", False)
        )
        return text


def extract_json(text: str) -> dict:
    """Parse the first JSON object in a model answer (tolerates code fences and chatter)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else text
    start = candidate.find("{")
    if start == -1:
        raise ValueError("no JSON object in model output")
    obj, _ = json.JSONDecoder().raw_decode(candidate[start:])
    if not isinstance(obj, dict):
        raise ValueError("model output is not a JSON object")
    return obj


def extract_code(text: str) -> str:
    fenced = re.search(r"```[\w-]*\n(.*?)```", text, re.S)
    return (fenced.group(1) if fenced else text).strip()
