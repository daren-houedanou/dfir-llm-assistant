# Jeu public : référence règles seules

Résultat des règles seules, sans modèle, sur les 8 enregistrements EVTX-ATTACK-SAMPLES, avant l'ajout des règles de l'essai 3.

| scénario | modèle | verdict | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| de-104-system-log-cleared | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-1102-security-log-cleared | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-fake-computeraccount-4720 | règles seules | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| kerberos-pwd-spray-4771 | règles seules | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-remote-service02-7045 | règles seules | ❌ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| network-service-guest-added-to-admins-4732 | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| powercat-revshell-sysmon-1-3 | règles seules | ❌ | 100% | 75% | 75% | 0.86 | 100% | – | 0 | 0 | 0.0s | 0 |
| powershell-4104-minidumpwritedump-lsass | règles seules | ✅ | 100% | 50% | 50% | 0.67 | 100% | – | 0 | 0 | 0.0s | 0 |

## Synthèse par modèle

| modèle | essais | verdicts justes | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|
| règles seules | 8 | 62% | 0.82 | 100% | – | 0 | 0.0s |

## Techniques manquées

- kerberos-pwd-spray-4771 / règles seules : T1110.003
- powercat-revshell-sysmon-1-3 / règles seules : T1059.001
- powershell-4104-minidumpwritedump-lsass / règles seules : T1059.001
