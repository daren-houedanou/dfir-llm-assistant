# Evaluation report

| scenario | model | verdict | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | rules | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |

## Aggregate per model

| model | runs | verdict acc. | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|
| rules | 4 | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
