# Public EVTX set: rules vs qwen2.5 14B / 7B

Run on 2026-11-23, Kaggle (Tesla T4, Ollama 0.40.17, context 16384, temperature 0, seed 42).
`dfir-local` = qwen2.5:14b-instruct, `dfir-local-small` = qwen2.5:7b-instruct. Single run per model.

| scenario | model | verdict | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 19.9s | 787 |
| de-104-system-log-cleared | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 9.4s | 819 |
| de-1102-security-log-cleared | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 36.8s | 6858 |
| de-1102-security-log-cleared | dfir-local-small | ❌ | 50% | 100% | 100% | 0.67 | 100% | n/a | 0 | 0 | 17.9s | 6979 |
| de-fake-computeraccount-4720 | rules | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 25.1s | 999 |
| de-fake-computeraccount-4720 | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 10.7s | 998 |
| kerberos-pwd-spray-4771 | rules | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 29.0s | 1961 |
| kerberos-pwd-spray-4771 | dfir-local-small | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 50.9s | 3090 |
| lm-remote-service02-7045 | rules | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 39.0s | 1364 |
| lm-remote-service02-7045 | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 15.6s | 1360 |
| network-service-guest-added-to-admins-4732 | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 37.6s | 1335 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 16.4s | 1374 |
| powercat-revshell-sysmon-1-3 | rules | ❌ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ❌ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 33.3s | 1612 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ❌ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 20.4s | 1830 |
| powershell-4104-minidumpwritedump-lsass | rules | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 0 | 0 | 23.0s | 1024 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 1 | 0 | 16.1s | 1214 |

## Aggregate per model

| model | runs | verdict acc. | mean F1 | mean IOC R | total leaks | median latency |
|---|---|---|---|---|---|---|
| rules | 8 | 62% | 0.82 | 100% | 0 | 0.0s |
| dfir-local (14B) | 8 | 12% | 0.82 | 100% | 0 | 31.1s |
| dfir-local-small (7B) | 8 | 25% | 0.77 | 100% | 0 | 16.3s |

## Missed techniques (all three)

- kerberos-pwd-spray-4771: T1110.003
- powercat-revshell-sysmon-1-3: T1059.001
- powershell-4104-minidumpwritedump-lsass: T1059.001

## Reading

- The models reach the same ATT&CK F1 as the rules but add almost nothing beyond the injected findings.
- Verdict accuracy is an exact match on `malicious`. These recordings are tiny (often one event), and a
  cautious `suspicious` counts as wrong; the lenient branch in `harness.py` was disabled by mistake.
  Confirmed by re-running `dfa summarize --json` with the 14B on each file: 7 of 8 answered `suspicious`,
  only the LSASS MiniDumpWriteDump one `malicious`. Counting suspicious-or-malicious as "danger seen",
  the 14B flags 8/8. The gap is verdict calibration, not detection.
- `dfa eval` does not write to the audit trail (the harness builds `LLMClient()` without an `AuditLog`).
- Kerberos spray (4771) and PowerShell execution context are missed by everyone: a rule gap the models
  do not fill on their own.
- No leak; one ungrounded IOC in 16 model runs.
