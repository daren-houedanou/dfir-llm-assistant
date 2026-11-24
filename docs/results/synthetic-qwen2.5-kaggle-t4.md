# Synthetic set: rules vs qwen2.5 14B / 7B

Run on 2026-11-23, Kaggle (Tesla T4, Ollama 0.40.17, context 16384, temperature 0, seed 42).
`dfir-local` = qwen2.5:14b-instruct, `dfir-local-small` = qwen2.5:7b-instruct. Single run per model.

| scenario | model | verdict | ATT&CK P | ATT&CK R | parent R | F1 | IOC R | Q&A | ungrounded | leaks | latency | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 216.3s | 22004 |
| benign-admin-day | dfir-local-small | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 69.5s | 21592 |
| linux-ssh-compromise | rules | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ | 100% | 50% | 50% | 0.67 | 80% | 100% | 0 | 0 | 214.4s | 35854 |
| linux-ssh-compromise | dfir-local-small | ✅ | 100% | 90% | 90% | 0.95 | 80% | 100% | 0 | 0 | 312.1s | 40540 |
| network-c2-exfil | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 130.7s | 28765 |
| network-c2-exfil | dfir-local-small | ✅ | 100% | 67% | 100% | 0.80 | 67% | 100% | 0 | 0 | 74.3s | 29074 |
| win-rdp-intrusion | rules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ | 100% | 77% | 77% | 0.87 | 100% | 100% | 0 | 0 | 220.7s | 34206 |
| win-rdp-intrusion | dfir-local-small | ✅ | 100% | 54% | 54% | 0.70 | 100% | 100% | 0 | 0 | 131.2s | 35792 |

## Aggregate per model

| model | runs | verdict acc. | mean F1 | mean IOC R | mean Q&A | total leaks | median latency |
|---|---|---|---|---|---|---|---|
| rules | 4 | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local (14B) | 4 | 50% | 0.63 | 95% | 75% | 0 | 215.3s |
| dfir-local-small (7B) | 4 | 75% | 0.61 | 87% | 75% | 0 | 102.7s |

## Missed techniques

- linux-ssh-compromise / dfir-local: T1021.004, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small: T1548.003
- network-c2-exfil / dfir-local-small: T1071.004
- win-rdp-intrusion / dfir-local: T1033, T1087, T1482
- win-rdp-intrusion / dfir-local-small: T1021.001, T1033, T1059.001, T1087, T1105, T1482

## Reading

- The rules win on this set, which was written together with them. The models add value on questions
  (Q&A 62% → 75%).
- Both models raise a false alarm on the benign day and invent techniques there (precision 0%).
- Verdict scoring is an exact match: a correct analysis labelled "suspicious" instead of "malicious"
  counts as wrong (network-c2-exfil / 14B).
- Answers are not reproducible run to run on GPU even at temperature 0 with a fixed seed; one run per
  model is not enough to rank 14B vs 7B.
- No privacy leak in any run.
