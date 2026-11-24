# Evaluation report

| scenario | model | verdict | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | rules | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | rules | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | rules | ❌ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | rules | ❌ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | rules | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 0 | 0 | 0.0s | 0 |

## Aggregate per model

| model | runs | verdict acc. | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|
| rules | 8 | 62% | 0.82 | 100% | n/a | 0 | 0.0s |

## Missed techniques

- kerberos-pwd-spray-4771 / rules: T1110.003
- powercat-revshell-sysmon-1-3 / rules: T1059.001
- powershell-4104-minidumpwritedump-lsass / rules: T1059.001
