# Essai 1, jeu synthétique : règles seules contre Qwen2.5 14B et 7B

Exécuté le 23/11/2026 sur Kaggle (Tesla T4, Ollama 0.40.17, contexte 16384, température 0, graine 42).
`dfir-local` = qwen2.5:14b-instruct, `dfir-local-small` = qwen2.5:7b-instruct. Un seul essai par modèle.

| scénario | modèle | verdict | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 216.3s | 22004 |
| benign-admin-day | dfir-local-small | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 69.5s | 21592 |
| linux-ssh-compromise | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ | 100% | 50% | 50% | 0.67 | 80% | 100% | 0 | 0 | 214.4s | 35854 |
| linux-ssh-compromise | dfir-local-small | ✅ | 100% | 90% | 90% | 0.95 | 80% | 100% | 0 | 0 | 312.1s | 40540 |
| network-c2-exfil | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 130.7s | 28765 |
| network-c2-exfil | dfir-local-small | ✅ | 100% | 67% | 100% | 0.80 | 67% | 100% | 0 | 0 | 74.3s | 29074 |
| win-rdp-intrusion | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ | 100% | 77% | 77% | 0.87 | 100% | 100% | 0 | 0 | 220.7s | 34206 |
| win-rdp-intrusion | dfir-local-small | ✅ | 100% | 54% | 54% | 0.70 | 100% | 100% | 0 | 0 | 131.2s | 35792 |

## Synthèse par modèle

| modèle | essais | verdicts justes | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|
| règles seules | 4 | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local (14B) | 4 | 50% | 0.63 | 95% | 75% | 0 | 215.3s |
| dfir-local-small (7B) | 4 | 75% | 0.61 | 87% | 75% | 0 | 102.7s |

## Techniques manquées

- linux-ssh-compromise / dfir-local : T1021.004, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small : T1548.003
- network-c2-exfil / dfir-local-small : T1071.004
- win-rdp-intrusion / dfir-local : T1033, T1087, T1482
- win-rdp-intrusion / dfir-local-small : T1021.001, T1033, T1059.001, T1087, T1105, T1482

## Lecture

- Les règles l'emportent sur ce jeu, écrit en même temps qu'elles. Les modèles apportent un gain sur les questions de l'analyste (Q/R de 62 % à 75 %).
- Les deux modèles donnent une fausse alerte sur la journée normale et y citent des techniques inexistantes (précision 0 %).
- Le verdict est compté juste uniquement s'il est identique : une analyse correcte conclue par « suspicious » au lieu de « malicious » compte comme fausse (network-c2-exfil, 14B).
- Un seul essai par modèle ne suffit pas pour départager le 14B et le 7B.
- Aucune fuite de donnée.
