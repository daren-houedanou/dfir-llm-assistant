# Essai 2 : critères de verdict dans le prompt (PROMPT_VERSION 2026-11-23.1)

Kaggle T4, mêmes modèles et réglages qu'à l'essai 1. Un seul essai par modèle.

## Jeu synthétique

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | règles seules | ✅ benign | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ suspicious | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 250.1s | 22648 |
| benign-admin-day | dfir-local-small | ✅ benign | ✅ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 72.9s | 21669 |
| linux-ssh-compromise | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ malicious | ✅ | 100% | 40% | 40% | 0.57 | 80% | 100% | 0 | 0 | 187.8s | 35923 |
| linux-ssh-compromise | dfir-local-small | ✅ malicious | ✅ | 100% | 60% | 60% | 0.75 | 80% | 100% | 0 | 0 | 230.7s | 40505 |
| network-c2-exfil | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 123.4s | 28970 |
| network-c2-exfil | dfir-local-small | ✅ malicious | ✅ | 100% | 67% | 50% | 0.80 | 67% | 100% | 0 | 0 | 59.2s | 29223 |
| win-rdp-intrusion | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ malicious | ✅ | 100% | 38% | 38% | 0.56 | 75% | 100% | 0 | 0 | 174.8s | 34128 |
| win-rdp-intrusion | dfir-local-small | ✅ malicious | ✅ | 100% | 69% | 69% | 0.82 | 100% | 100% | 0 | 0 | 95.4s | 35211 |

### Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 4 | 100% | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local | 4 | 75% | 75% | 0.53 | 89% | 75% | 0 | 181.3s |
| dfir-local-small | 4 | 100% | 100% | 0.59 | 87% | 75% | 0 | 84.2s |

### Techniques manquées

- linux-ssh-compromise / dfir-local : T1021.004, T1053.003, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small : T1021.004, T1098, T1105, T1548.003
- network-c2-exfil / dfir-local-small : T1048
- win-rdp-intrusion / dfir-local : T1021.001, T1027, T1033, T1078, T1087, T1098, T1105, T1482
- win-rdp-intrusion / dfir-local-small : T1033, T1059.001, T1087, T1482

## Jeu public

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 18.9s | 966 |
| de-104-system-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 8.3s | 956 |
| de-1102-security-log-cleared | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 45.5s | 7027 |
| de-1102-security-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 15.0s | 6929 |
| de-fake-computeraccount-4720 | règles seules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 25.5s | 1149 |
| de-fake-computeraccount-4720 | dfir-local-small | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 7.7s | 1091 |
| kerberos-pwd-spray-4771 | règles seules | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 28.5s | 2087 |
| kerberos-pwd-spray-4771 | dfir-local-small | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 16.3s | 2306 |
| lm-remote-service02-7045 | règles seules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 37.8s | 1531 |
| lm-remote-service02-7045 | dfir-local-small | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 12.4s | 1471 |
| network-service-guest-added-to-admins-4732 | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 2 | 0 | 24.3s | 1314 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 10.9s | 1359 |
| powercat-revshell-sysmon-1-3 | règles seules | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 32.3s | 1745 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ❌ suspicious | ✅ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 13.0s | 1761 |
| powershell-4104-minidumpwritedump-lsass | règles seules | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 1 | 0 | 18.9s | 1130 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ malicious | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 1 | 0 | 11.6s | 1268 |

### Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 8 | 62% | 100% | 0.82 | 100% | – | 0 | 0.0s |
| dfir-local | 8 | 62% | 100% | 0.82 | 100% | – | 0 | 27.0s |
| dfir-local-small | 8 | 62% | 100% | 0.82 | 100% | – | 0 | 12.0s |

### Techniques manquées

- kerberos-pwd-spray-4771 / règles seules : T1110.003
- kerberos-pwd-spray-4771 / dfir-local : T1110.003
- kerberos-pwd-spray-4771 / dfir-local-small : T1110.003
- powercat-revshell-sysmon-1-3 / règles seules : T1059.001
- powercat-revshell-sysmon-1-3 / dfir-local : T1059.001
- powercat-revshell-sysmon-1-3 / dfir-local-small : T1059.001
- powershell-4104-minidumpwritedump-lsass / règles seules : T1059.001
- powershell-4104-minidumpwritedump-lsass / dfir-local : T1059.001
- powershell-4104-minidumpwritedump-lsass / dfir-local-small : T1059.001

## Avant / après (verdicts justes)

| jeu | modèle | essai 1 | essai 2 |
|---|---|---|---|
| synthétique | 14B | 50% | 75% |
| synthétique | 7B | 75% | 100% |
| public | 14B | 12% | 62% |
| public | 7B | 25% | 62% |

## Lecture

- Les critères de verdict ont corrigé l'étalonnage : sur le jeu public, chaque modèle signale les 8 attaques et donne exactement le verdict des règles. Le 7B ne donne plus de fausse alerte sur la journée normale ; le 14B répond encore « suspicious ».
- Les verdicts encore faux (faux compte machine, service distant, powercat) correspondent à des scénarios dont la preuve la plus forte est MEDIUM : le manque vient maintenant de la gravité donnée par les règles, pas du modèle.
- Effet secondaire : moins de techniques citées sur le jeu synthétique (F1 moyen 14B 0.63 → 0.53, 7B 0.61 → 0.59), et des techniques encore citées avec un verdict « benign » (précision 0 % sur la journée normale). Un seul essai : `--repeat` permettrait de distinguer cet effet de la variabilité.
- Indicateurs non fondés sur le jeu public : 3 (14B) et 1 (7B), contre 0 et 1 à l'essai 1. Aucune fuite.
