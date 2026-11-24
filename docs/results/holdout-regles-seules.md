# Jeu holdout : référence règles seules

Dix enregistrements EVTX-ATTACK-SAMPLES choisis uniquement d'après leur libellé, avant d'y exécuter la moindre règle, et jamais utilisés pour écrire ou ajuster une règle. Les techniques attendues viennent des noms de fichiers et des dossiers du jeu de données.

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ca-comsvcs-minidump-lsass | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| ca-dcsync-4662 | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-uac-disabled | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| exec-regsvr32-sct | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| exec-temp-scheduled-task | règles seules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-psexec-meterpreter | règles seules | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-wmiexec-impacket | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| pe-uac-bypass-eventvwr | règles seules | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| persist-accessibility-osk | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| persist-local-admin-account-sysmon | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |

## Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 10 | 20% | 40% | 0.20 | 100% | – | 0 | 0.0s |

## Techniques manquées

- ca-dcsync-4662 / règles seules : T1003.006
- de-uac-disabled / règles seules : T1548.002
- exec-regsvr32-sct / règles seules : T1218.010
- lm-psexec-meterpreter / règles seules : T1021.002, T1569.002
- lm-wmiexec-impacket / règles seules : T1047
- pe-uac-bypass-eventvwr / règles seules : T1548.002
- persist-accessibility-osk / règles seules : T1546.008
- persist-local-admin-account-sysmon / règles seules : T1098, T1136.001
