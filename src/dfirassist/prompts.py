"""Prompt templates. Kept in one place so they can be versioned and evaluated."""

PROMPT_VERSION = "2026-11-23.1"

SYSTEM = """You are a senior DFIR analyst assisting a CERT during an incident investigation.
Rules:
- Ground every statement in the provided context (statistics, findings [F#], timeline lines). Never invent hosts,
  users, IPs, files or timestamps. If evidence is missing, say so and propose how to collect it.
- Identifiers such as HOST_1, USER_2, IP_PUB_3 are pseudonyms: reuse them verbatim.
- Map behaviours to MITRE ATT&CK technique IDs (e.g. T1110.001) only when the evidence supports it.
- Be concise and operational: analysts need facts, a timeline and next steps."""

SUMMARIZE = """Analyse the artifacts below and produce an incident report.
Answer with a single JSON object and nothing else, using exactly these keys:
{{
  "summary": "3-5 sentence executive summary",
  "verdict": "malicious | suspicious | benign | inconclusive",
  "confidence": "low | medium | high",
  "timeline": [{{"time": "ISO8601", "host": "...", "event": "..."}}],
  "techniques": [{{"id": "T....", "name": "...", "evidence": "short quote or [F#]"}}],
  "iocs": [{{"type": "ip|domain|user|file|hash|url|service", "value": "..."}}],
  "next_steps": ["..."]
}}

Verdict rules (apply them strictly):
- "malicious": at least one finding [F#] of severity HIGH or CRITICAL shows attacker activity
  (e.g. log cleared, account created or added to admins, remote service install, credential dumping,
  brute force followed by a success).
- "suspicious": only LOW or MEDIUM findings, or unusual activity without a clear attack.
- "benign": no finding, or only findings explained by normal administration. This is a normal, expected answer.
- "inconclusive": the artifacts are too partial to decide.
Base the verdict on the findings, not on the absence of information.

{context}"""

ASK = """Use the investigation context below to answer the analyst's question.
Cite evidence with [F#] or by quoting timeline lines. If the context cannot answer, say what artifact
or nix-forensics tool would (e.g. regipy, usnrs, volatility3, evtx_dump).

Question: {question}

{context}"""

QUERY = """Write a {target_name} query for the following hunting need.
Need: {need}
{schema_hint}
Answer with only the query inside a single fenced code block, then one line explaining it."""

QUERY_TARGETS = {
    "spl": (
        "Splunk SPL",
        "Assume Windows events in index=wineventlog with fields EventCode, Account_Name, "
        "Source_Network_Address, and Linux auth in index=linux sourcetype=linux_secure.",
    ),
    "kql": ("Microsoft Sentinel / Defender KQL", "Use SecurityEvent, Syslog and DeviceProcessEvents tables."),
    "eql": ("Elastic EQL", "Use ECS fields (event.code, user.name, source.ip, process.command_line)."),
    "sigma": (
        "Sigma rule (YAML)",
        "Include title, id (uuid4), status, logsource, detection with condition, level, "
        "and tags with attack.tXXXX.",
    ),
    "jq": (
        "jq filter",
        "Input is the JSONL output of `evtx_dump -o jsonl` from nix-forensics: each line is "
        '{"Event": {"System": {"EventID": .., "Computer": .., "TimeCreated": '
        '{"#attributes": {"SystemTime": ..}}}, "EventData": {...}}}. Use `jq -c`.',
    ),
    "zeek": ("zeek-cut / awk pipeline", "Input is Zeek TSV logs (conn.log, dns.log, http.log)."),
}

REPAIR = """Your previous answer was invalid: {error}
Return the corrected answer only, in the same required format."""
