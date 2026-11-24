# Hold-out set: rules-only baseline

Ten EVTX-ATTACK-SAMPLES recordings chosen by their labels only, before running any rule on them, and
not used to write or tune rules. Labels (expected techniques) come from the file names and the dataset
folders.

| scenario | model | verdict | danger seen | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ca-comsvcs-minidump-lsass | rules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| ca-dcsync-4662 | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| de-uac-disabled | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| exec-regsvr32-sct | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| exec-temp-scheduled-task | rules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-psexec-meterpreter | rules | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| lm-wmiexec-impacket | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| pe-uac-bypass-eventvwr | rules | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| persist-accessibility-osk | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |
| persist-local-admin-account-sysmon | rules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | n/a | 0 | 0 | 0.0s | 0 |

## Aggregate per model

| model | runs | verdict acc. | danger seen | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|---|
| rules | 10 | 20% | 40% | 0.20 | 100% | n/a | 0 | 0.0s |

## Missed techniques

- ca-dcsync-4662 / rules: T1003.006
- de-uac-disabled / rules: T1548.002
- exec-regsvr32-sct / rules: T1218.010
- lm-psexec-meterpreter / rules: T1021.002, T1569.002
- lm-wmiexec-impacket / rules: T1047
- pe-uac-bypass-eventvwr / rules: T1548.002
- persist-accessibility-osk / rules: T1546.008
- persist-local-admin-account-sysmon / rules: T1098, T1136.001
