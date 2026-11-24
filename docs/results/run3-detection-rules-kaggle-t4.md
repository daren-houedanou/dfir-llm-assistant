# Run 3: new detection rules (main fd21455)

Kaggle T4, same models, prompt and settings as run 2. Single run per model.

## Public set

| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 21.1s | 966 |
| de-104-system-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 9.2s | 956 |
| de-1102-security-log-cleared | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 49.3s | 7027 |
| de-1102-security-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 16.1s | 6929 |
| de-fake-computeraccount-4720 | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 23.5s | 1170 |
| de-fake-computeraccount-4720 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 10.2s | 1184 |
| kerberos-pwd-spray-4771 | rules | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | n/a | 0 | 0 | 44.6s | 2754 |
| kerberos-pwd-spray-4771 | dfir-local-small | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | n/a | 0 | 0 | 21.6s | 2909 |
| lm-remote-service02-7045 | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 34.6s | 1519 |
| lm-remote-service02-7045 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 13.9s | 1514 |
| network-service-guest-added-to-admins-4732 | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 2 | 0 | 27.4s | 1352 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 11.1s | 1376 |
| powercat-revshell-sysmon-1-3 | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 50.1s | 2280 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 15.7s | 2155 |
| powershell-4104-minidumpwritedump-lsass | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 1 | 0 | 19.5s | 1170 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 2 | 0 | 14.0s | 1371 |

### Aggregate per model

| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|---|
| rules | 8 | 100% | 100% | 0.96 | 100% | n/a | 0 | 0.0s |
| dfir-local | 8 | 100% | 100% | 0.96 | 100% | n/a | 0 | 31.0s |
| dfir-local-small | 8 | 100% | 100% | 0.96 | 100% | n/a | 0 | 13.9s |

## Synthetic set

| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | rules | ✅ benign | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ suspicious | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 240.9s | 22648 |
| benign-admin-day | dfir-local-small | ✅ benign | ✅ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 75.0s | 21669 |
| linux-ssh-compromise | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ malicious | ✅ | 100% | 40% | 40% | 0.57 | 80% | 100% | 0 | 0 | 199.8s | 35923 |
| linux-ssh-compromise | dfir-local-small | ✅ malicious | ✅ | 100% | 60% | 60% | 0.75 | 80% | 100% | 0 | 0 | 262.3s | 40505 |
| network-c2-exfil | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 140.4s | 28970 |
| network-c2-exfil | dfir-local-small | ✅ malicious | ✅ | 100% | 67% | 50% | 0.80 | 67% | 100% | 0 | 0 | 63.2s | 29223 |
| win-rdp-intrusion | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ malicious | ✅ | 100% | 38% | 38% | 0.56 | 75% | 100% | 0 | 0 | 192.7s | 34128 |
| win-rdp-intrusion | dfir-local-small | ✅ malicious | ✅ | 100% | 69% | 69% | 0.82 | 100% | 100% | 0 | 0 | 103.1s | 35211 |

### Aggregate per model

| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|---|
| rules | 4 | 100% | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local | 4 | 75% | 75% | 0.53 | 89% | 75% | 0 | 196.3s |
| dfir-local-small | 4 | 100% | 100% | 0.59 | 87% | 75% | 0 | 89.1s |

### Missed techniques

- linux-ssh-compromise / dfir-local: T1021.004, T1053.003, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small: T1021.004, T1098, T1105, T1548.003
- network-c2-exfil / dfir-local-small: T1048
- win-rdp-intrusion / dfir-local: T1021.001, T1027, T1033, T1078, T1087, T1098, T1105, T1482
- win-rdp-intrusion / dfir-local-small: T1033, T1059.001, T1087, T1482

## Verdict accuracy across runs

| set | model | run 1 (baseline) | run 2 (verdict rules in prompt) | run 3 (+ detection rules) |
|---|---|---|---|---|
| public | rules | 62% | 62% | 100% |
| public | 14B | 12% | 62% | 100% |
| public | 7B | 25% | 62% | 100% |
| synthetic | 14B | 50% | 75% | 75% |
| synthetic | 7B | 75% | 100% | 100% |

## Reading

- Public set: every model now gets every verdict right, F1 0.96, Kerberos spray and PowerShell no longer
  missed. The models give exactly the rules' verdict: with the verdict rules in the prompt, the LLM
  follows finding severity. The new rules were written while looking at this set, so this needs
  confirming on unseen samples.
- Synthetic set: unchanged from run 2 (the new rules do not fire there), and token counts are identical
  to run 2 for every run: same prompt, same model, same answer across two separate Kaggle sessions.
- Still open: the 14B calls the benign day "suspicious"; models list techniques even on a "benign"
  verdict; technique recall on the synthetic set is low (mean F1 0.53 / 0.59).
