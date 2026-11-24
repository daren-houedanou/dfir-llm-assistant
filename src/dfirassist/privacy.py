"""Reversible pseudonymization applied before any prompt leaves the trust boundary.

Hostnames, usernames, IP addresses, e-mails and domains are replaced by stable tokens
(``HOST_1``, ``USER_2``, ``IP_PRIV_1``, ``IP_PUB_3``...) that keep the *semantics*
the model needs (internal vs external IP, same entity across events) while hiding
the identifying values. The model answer is rehydrated locally.

This is the safeguard that lets an analyst use a stronger cloud model on
non-confidential cases without sending raw investigation data.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .models import Event

IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
FQDN_RE = re.compile(
    r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|fr|eu|local|corp|lan|internal|info|biz|ru|cn|xyz|top)\b", re.I
)
# RFC1918, CGNAT, link-local and ULA: "internal" for the model. Note that Python's ``is_private`` also
# flags documentation ranges (TEST-NET), which would wrongly hide that an address is external.
INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
]
# Values that are not identifying and must stay readable for the model.
KEEP = {
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "-",
    "",
    "root",
    "administrator",
    "admin",
    "guest",
    "localhost",
}


@dataclass
class Pseudonymizer:
    keep_public_ips: bool = False
    forward: dict[str, str] = field(default_factory=dict)
    originals: dict[str, str] = field(default_factory=dict)  # token -> value as first seen (original case)
    counters: dict[str, int] = field(default_factory=dict)

    def _token(self, kind: str, value: str) -> str:
        key = value.lower() if kind != "IP" else value
        if key in self.forward:
            return self.forward[key]
        if kind == "IP":
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return value
            if ip.is_loopback or ip.is_unspecified:
                return value
            internal = any(ip in net for net in INTERNAL_NETS)
            if not internal and self.keep_public_ips:
                return value
            kind = "IP_PRIV" if internal else "IP_PUB"
        self.counters[kind] = self.counters.get(kind, 0) + 1
        token = f"{kind}_{self.counters[kind]}"
        self.forward[key] = token
        self.originals[token] = value
        return token

    @property
    def reverse(self) -> dict[str, str]:
        return dict(self.originals)

    def register_event(self, event: Event) -> None:
        """Learn entity names from structured fields so free text mentioning them is also masked."""
        if event.host and event.host.lower() not in KEEP:
            self._token("HOST", event.host)
            short = event.host.split(".")[0]
            if short.lower() != event.host.lower():
                self.forward.setdefault(short.lower(), self.forward[event.host.lower()])
        if event.user and event.user.lower() not in KEEP:
            self._token("USER", event.user)

    def mask(self, text: str) -> str:
        text = EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), text)
        text = IPV4_RE.sub(lambda m: self._token("IP", m.group(0)), text)
        text = FQDN_RE.sub(lambda m: self._token("DOMAIN", m.group(0)), text)
        # Replace learned host/user names (longest first so FQDNs win over short names).
        names = sorted(
            (k for k, v in self.forward.items() if v.startswith(("HOST_", "USER_"))), key=len, reverse=True
        )
        if names:
            pattern = re.compile(r"(?<![\w-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])", re.I)
            text = pattern.sub(lambda m: self.forward[m.group(0).lower()], text)
        return text

    def unmask(self, text: str) -> str:
        reverse = self.reverse
        if not reverse:
            return text
        pattern = re.compile(
            r"\b(" + "|".join(re.escape(t) for t in sorted(reverse, key=len, reverse=True)) + r")\b"
        )
        return pattern.sub(lambda m: reverse[m.group(0)], text)

    def leaked(self, text: str) -> list[str]:
        """Return original sensitive values still present in ``text`` (used by tests and eval)."""
        return [
            orig
            for orig in self.forward
            if len(orig) > 3 and re.search(r"(?<![\w-])" + re.escape(orig) + r"(?![\w-])", text, re.I)
        ]
