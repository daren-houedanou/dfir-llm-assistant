# Essai 3 : nouvelles règles de détection

Kaggle T4, mêmes modèles, prompt et réglages qu'à l'essai 2. Un seul essai par modèle.

## Jeu public

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 21.1s | 966 |
| de-104-system-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 9.2s | 956 |
| de-1102-security-log-cleared | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 49.3s | 7027 |
| de-1102-security-log-cleared | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 16.1s | 6929 |
| de-fake-computeraccount-4720 | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 23.5s | 1170 |
| de-fake-computeraccount-4720 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 10.2s | 1184 |
| kerberos-pwd-spray-4771 | règles seules | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | – | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | – | 0 | 0 | 44.6s | 2754 |
| kerberos-pwd-spray-4771 | dfir-local-small | ✅ malicious | ✅ | 50% | 100% | 100% | 0.67 | 100% | – | 0 | 0 | 21.6s | 2909 |
| lm-remote-service02-7045 | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 34.6s | 1519 |
| lm-remote-service02-7045 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 13.9s | 1514 |
| network-service-guest-added-to-admins-4732 | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 2 | 0 | 27.4s | 1352 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 11.1s | 1376 |
| powercat-revshell-sysmon-1-3 | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 50.1s | 2280 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 15.7s | 2155 |
| powershell-4104-minidumpwritedump-lsass | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 1 | 0 | 19.5s | 1170 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 2 | 0 | 14.0s | 1371 |

### Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 8 | 100% | 100% | 0.96 | 100% | – | 0 | 0.0s |
| dfir-local | 8 | 100% | 100% | 0.96 | 100% | – | 0 | 31.0s |
| dfir-local-small | 8 | 100% | 100% | 0.96 | 100% | – | 0 | 13.9s |

## Jeu synthétique

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | règles seules | ✅ benign | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| benign-admin-day | dfir-local | ❌ suspicious | ❌ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 240.9s | 22648 |
| benign-admin-day | dfir-local-small | ✅ benign | ✅ | 0% | 100% | 100% | 0.00 | 100% | 0% | 0 | 0 | 75.0s | 21669 |
| linux-ssh-compromise | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | dfir-local | ✅ malicious | ✅ | 100% | 40% | 40% | 0.57 | 80% | 100% | 0 | 0 | 199.8s | 35923 |
| linux-ssh-compromise | dfir-local-small | ✅ malicious | ✅ | 100% | 60% | 60% | 0.75 | 80% | 100% | 0 | 0 | 262.3s | 40505 |
| network-c2-exfil | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 140.4s | 28970 |
| network-c2-exfil | dfir-local-small | ✅ malicious | ✅ | 100% | 67% | 50% | 0.80 | 67% | 100% | 0 | 0 | 63.2s | 29223 |
| win-rdp-intrusion | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | dfir-local | ✅ malicious | ✅ | 100% | 38% | 38% | 0.56 | 75% | 100% | 0 | 0 | 192.7s | 34128 |
| win-rdp-intrusion | dfir-local-small | ✅ malicious | ✅ | 100% | 69% | 69% | 0.82 | 100% | 100% | 0 | 0 | 103.1s | 35211 |

### Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 4 | 100% | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
| dfir-local | 4 | 75% | 75% | 0.53 | 89% | 75% | 0 | 196.3s |
| dfir-local-small | 4 | 100% | 100% | 0.59 | 87% | 75% | 0 | 89.1s |

### Techniques manquées

- linux-ssh-compromise / dfir-local : T1021.004, T1053.003, T1078, T1098, T1105, T1548.003
- linux-ssh-compromise / dfir-local-small : T1021.004, T1098, T1105, T1548.003
- network-c2-exfil / dfir-local-small : T1048
- win-rdp-intrusion / dfir-local : T1021.001, T1027, T1033, T1078, T1087, T1098, T1105, T1482
- win-rdp-intrusion / dfir-local-small : T1033, T1059.001, T1087, T1482

## Verdicts justes d'un essai à l'autre

| jeu | modèle | essai 1 (départ) | essai 2 (critères de verdict) | essai 3 (+ règles de détection) |
|---|---|---|---|---|
| public | règles seules | 62% | 62% | 100% |
| public | 14B | 12% | 62% | 100% |
| public | 7B | 25% | 62% | 100% |
| synthétique | 14B | 50% | 75% | 75% |
| synthétique | 7B | 75% | 100% | 100% |

## Lecture

- Jeu public : tous les verdicts sont justes pour tous les modèles, F1 0.96 ; le spray Kerberos et PowerShell ne sont plus manqués. Les modèles donnent exactement le verdict des règles : avec les critères de verdict, le modèle suit la gravité des preuves. Les nouvelles règles ont été écrites en regardant ce jeu, ce résultat devait donc être confirmé sur des enregistrements jamais vus (voir `holdout-regles-seules.md`).
- Jeu synthétique : identique à l'essai 2 (les nouvelles règles ne s'y déclenchent pas), avec le même nombre de tokens pour chaque réponse : même prompt, même modèle, même réponse sur deux sessions Kaggle distinctes.
- Reste ouvert : le 14B qualifie la journée normale de « suspicious » ; les modèles citent des techniques même avec un verdict « benign » ; le rappel des techniques reste faible sur le jeu synthétique (F1 moyen 0.53 et 0.59).
