# Essai 1, jeu public : règles seules contre Qwen2.5 14B et 7B

Exécuté le 23/11/2026 sur Kaggle (Tesla T4, Ollama 0.40.17, contexte 16384, température 0, graine 42).
`dfir-local` = qwen2.5:14b-instruct, `dfir-local-small` = qwen2.5:7b-instruct. Un seul essai par modèle.

| scénario | modèle | verdict | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-104-system-log-cleared | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 19.9s | 787 |
| de-104-system-log-cleared | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 9.4s | 819 |
| de-1102-security-log-cleared | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 36.8s | 6858 |
| de-1102-security-log-cleared | dfir-local-small | ❌ | 50% | 100% | 100% | 0.67 | 100% | – | 0 | 0 | 17.9s | 6979 |
| de-fake-computeraccount-4720 | règles seules | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 25.1s | 999 |
| de-fake-computeraccount-4720 | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 10.7s | 998 |
| kerberos-pwd-spray-4771 | règles seules | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | dfir-local | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 29.0s | 1961 |
| kerberos-pwd-spray-4771 | dfir-local-small | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 50.9s | 3090 |
| lm-remote-service02-7045 | règles seules | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 39.0s | 1364 |
| lm-remote-service02-7045 | dfir-local-small | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 15.6s | 1360 |
| network-service-guest-added-to-admins-4732 | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | dfir-local | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 37.6s | 1335 |
| network-service-guest-added-to-admins-4732 | dfir-local-small | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 16.4s | 1374 |
| powercat-revshell-sysmon-1-3 | règles seules | ❌ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | dfir-local | ❌ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 33.3s | 1612 |
| powercat-revshell-sysmon-1-3 | dfir-local-small | ❌ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 20.4s | 1830 |
| powershell-4104-minidumpwritedump-lsass | règles seules | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | dfir-local | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 0 | 0 | 23.0s | 1024 |
| powershell-4104-minidumpwritedump-lsass | dfir-local-small | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 1 | 0 | 16.1s | 1214 |

## Synthèse par modèle

| modèle | essais | verdicts justes | F1 moyen | IOC R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|
| règles seules | 8 | 62% | 0.82 | 100% | 0 | 0.0s |
| dfir-local (14B) | 8 | 12% | 0.82 | 100% | 0 | 31.1s |
| dfir-local-small (7B) | 8 | 25% | 0.77 | 100% | 0 | 16.3s |

## Techniques manquées (par les trois)

- kerberos-pwd-spray-4771 : T1110.003
- powercat-revshell-sysmon-1-3 : T1059.001
- powershell-4104-minidumpwritedump-lsass : T1059.001

## Lecture

- Les modèles atteignent le même F1 ATT&CK que les règles, mais n'ajoutent presque rien aux preuves qui leur sont fournies.
- Le verdict doit être exactement `malicious`. Ces enregistrements sont très courts (souvent un seul événement) et un « suspicious » prudent compte comme faux. Vérification avec `dfa summarize --json` et le 14B sur chaque fichier : 7 réponses sur 8 sont `suspicious`, seule celle du dump LSASS est `malicious`. En comptant « suspicious ou malicious » comme danger vu, le 14B signale 8 attaques sur 8. Le problème est l'étalonnage du verdict, pas la détection.
- Le spray Kerberos (4771) et le contexte d'exécution PowerShell ne sont vus par personne : c'est un manque des règles que les modèles ne comblent pas seuls.
- Aucune fuite ; un indicateur non fondé sur 16 réponses de modèles.
