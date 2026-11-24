# Run 2: verdict rules in the prompt (PROMPT_VERSION 2026-11-23.1)

Kaggle T4, same models and settings as run 1. Single run per model.

## Synthetic set

| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | rules | ✅ benign | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ suspicious | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 250.1s | 22648 |
| benign-admin-day | dfir-local-small | ✅ benign | ✅ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 72.9s | 21669 |
| linux-ssh-compromise | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ malicious | ✅ | 100% | 40% | 40% | 0.57 | 80% | 100% | 0 | 0 | 187.8s | 35923 |
| linux-ssh-compromise | dfir-local-small | ✅ malicious | ✅ | 100% | 60% | 60% | 0.75 | 80% | 100% | 0 | 0 | 230.7s | 40505 |
| network-c2-exfil | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 123.4s | 28970 |
| network-c2-exfil | dfir-local-small | ✅ malicious | ✅ | 100% | 67% | 50% | 0.80 | 67% | 100% | 0 | 0 | 59.2s | 29223 |
| win-rdp-intrusion | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ malicious | ✅ | 100% | 38% | 38% | 0.56 | 75% | 100% | 0 | 0 | 174.8s | 34128 |
| win-rdp-intrusion | dfir-local-small | ✅ malicious | ✅ | 100% | 69% | 69% | 0.82 | 100% | 100% | 0 | 0 | 95.4s | 35211 |

### Aggregate per model

| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|---|
| rules | 4 | 100% | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local | 4 | 75% | 75% | 0.53 | 89% | 75% | 0 | 181.3s |
| dfir-local-small | 4 | 100% | 100% | 0.59 | 87% | 75% | 0 | 84.2s |

### Missed techniques

- linux-ssh-compromise / dfir-local: T1021.004, T1053.003, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small: T1021.004, T1098, T1105, T1548.003
- network-c2-exfil / dfir-local-small: T1048
- win-rdp-intrusion / dfir-local: T1021.001, T1027, T1033, T1078, T1087, T1098, T1105, T1482
- win-rdp-intrusion / dfir-local-small: T1033, T1059.001, T1087, T1482

## Public set

| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 18.9s | 966 |
| de-104-system-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 8.3s | 956 |
| de-1102-security-log-cleared | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 45.5s | 7027 |
| de-1102-security-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 15.0s | 6929 |
| de-fake-computeraccount-4720 | rules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 25.5s | 1149 |
| de-fake-computeraccount-4720 | dfir-local-small | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 7.7s | 1091 |
| kerberos-pwd-spray-4771 | rules | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 28.5s | 2087 |
| kerberos-pwd-spray-4771 | dfir-local-small | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 16.3s | 2306 |
| lm-remote-service02-7045 | rules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 37.8s | 1531 |
| lm-remote-service02-7045 | dfir-local-small | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 12.4s | 1471 |
| network-service-guest-added-to-admins-4732 | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 2 | 0 | 24.3s | 1314 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 10.9s | 1359 |
| powercat-revshell-sysmon-1-3 | rules | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 32.3s | 1745 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | n/a | 0 | 0 | 13.0s | 1761 |
| powershell-4104-minidumpwritedump-lsass | rules | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 1 | 0 | 18.9s | 1130 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | n/a | 1 | 0 | 11.6s | 1268 |

### Aggregate per model

| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|---|
| rules | 8 | 62% | 100% | 0.82 | 100% | n/a | 0 | 0.0s |
| dfir-local | 8 | 62% | 100% | 0.82 | 100% | n/a | 0 | 27.0s |
| dfir-local-small | 8 | 62% | 100% | 0.82 | 100% | n/a | 0 | 12.0s |

### Missed techniques

- kerberos-pwd-spray-4771 / rules: T1110.003
- kerberos-pwd-spray-4771 / dfir-local: T1110.003
- kerberos-pwd-spray-4771 / dfir-local-small: T1110.003
- powercat-revshell-sysmon-1-3 / rules: T1059.001
- powercat-revshell-sysmon-1-3 / dfir-local: T1059.001
- powercat-revshell-sysmon-1-3 / dfir-local-small: T1059.001
- powershell-4104-minidumpwritedump-lsass / rules: T1059.001
- powershell-4104-minidumpwritedump-lsass / dfir-local: T1059.001
- powershell-4104-minidumpwritedump-lsass / dfir-local-small: T1059.001

## Before / after (verdict accuracy)

| set | model | run 1 | run 2 |
|---|---|---|---|
| synthetic | 14B | 50% | 75% |
| synthetic | 7B | 75% | 100% |
| public | 14B | 12% | 62% |
| public | 7B | 25% | 62% |

## Reading

- The verdict rules fixed calibration: on the public set every model now flags 8/8 attacks and gives
  exactly the rules' verdict. The 7B no longer raises a false alarm on the benign day; the 14B still
  says "suspicious" there.
- The remaining verdict misses (fake computer account, remote service, powercat) are scenarios where
  the strongest finding is MEDIUM: the gap is now in rule severities, not in the model.
- Side effect: fewer techniques cited on the synthetic set (mean F1 14B 0.63 → 0.53, 7B 0.61 → 0.59),
  and "benign" verdicts still come with techniques (precision 0% on the benign day). One run only;
  use `--repeat` to separate this from run-to-run variance.
- Ungrounded IOCs: 3 (14B) and 1 (7B) on the public set, up from 0 and 1. No leak.
