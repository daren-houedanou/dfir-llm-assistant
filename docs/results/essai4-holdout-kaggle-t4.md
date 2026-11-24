# Essai 4, jeu holdout : règles seules contre Qwen2.5 14B et 7B

Kaggle T4, mêmes modèles, prompt, règles et réglages qu'à l'essai 3. Dix enregistrements EVTX-ATTACK-SAMPLES jamais utilisés pour écrire ou ajuster une règle ; le verdict attendu est `malicious` pour tous. Un seul essai par modèle.

| scénario | modèle | verdict | danger vu | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ca-comsvcs-minidump-lsass | règles seules | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| ca-comsvcs-minidump-lsass | dfir-local | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 1 | 0 | 36.3s | 1547 |
| ca-comsvcs-minidump-lsass | dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 19.9s | 1578 |
| ca-dcsync-4662 | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| ca-dcsync-4662 | dfir-local | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 12.9s | 877 |
| ca-dcsync-4662 | dfir-local-small | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 7.7s | 879 |
| de-uac-disabled | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| de-uac-disabled | dfir-local | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 12.1s | 920 |
| de-uac-disabled | dfir-local-small | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 6.7s | 904 |
| exec-regsvr32-sct | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| exec-regsvr32-sct | dfir-local | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 29.6s | 1269 |
| exec-regsvr32-sct | dfir-local-small | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 17.9s | 1360 |
| exec-temp-scheduled-task | règles seules | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| exec-temp-scheduled-task | dfir-local | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 0 | 0 | 20.9s | 1103 |
| exec-temp-scheduled-task | dfir-local-small | ❌ suspicious | ✅ | 100% | 100% | 100% | 1.00 | 100% | – | 1 | 0 | 20.9s | 1322 |
| lm-psexec-meterpreter | règles seules | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-psexec-meterpreter | dfir-local | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 31.0s | 2132 |
| lm-psexec-meterpreter | dfir-local-small | ✅ malicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 19.0s | 2230 |
| lm-wmiexec-impacket | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| lm-wmiexec-impacket | dfir-local | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 39.6s | 1711 |
| lm-wmiexec-impacket | dfir-local-small | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 25.9s | 1878 |
| pe-uac-bypass-eventvwr | règles seules | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| pe-uac-bypass-eventvwr | dfir-local | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 18.0s | 1393 |
| pe-uac-bypass-eventvwr | dfir-local-small | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 22.9s | 1698 |
| persist-accessibility-osk | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| persist-accessibility-osk | dfir-local | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 24.9s | 1117 |
| persist-accessibility-osk | dfir-local-small | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 8.9s | 981 |
| persist-local-admin-account-sysmon | règles seules | ❌ benign | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 0.0s | 0 |
| persist-local-admin-account-sysmon | dfir-local | ❌ inconclusive | ❌ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 25.3s | 1776 |
| persist-local-admin-account-sysmon | dfir-local-small | ❌ suspicious | ✅ | 0% | 0% | 0% | 0.00 | 100% | – | 0 | 0 | 29.4s | 2217 |

## Synthèse par modèle

| modèle | essais | verdicts justes | danger vu | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|---|
| règles seules | 10 | 20% | 40% | 0.20 | 100% | – | 0 | 0.0s |
| dfir-local | 10 | 20% | 80% | 0.20 | 100% | – | 0 | 25.1s |
| dfir-local-small | 10 | 20% | 70% | 0.20 | 100% | – | 0 | 19.5s |

## Techniques manquées

- ca-dcsync-4662 / règles seules : T1003.006
- ca-dcsync-4662 / dfir-local : T1003.006
- ca-dcsync-4662 / dfir-local-small : T1003.006
- de-uac-disabled / règles seules : T1548.002
- de-uac-disabled / dfir-local : T1548.002
- de-uac-disabled / dfir-local-small : T1548.002
- exec-regsvr32-sct / règles seules : T1218.010
- exec-regsvr32-sct / dfir-local : T1218.010
- exec-regsvr32-sct / dfir-local-small : T1218.010
- lm-psexec-meterpreter / règles seules : T1021.002, T1569.002
- lm-psexec-meterpreter / dfir-local : T1021.002, T1569.002
- lm-psexec-meterpreter / dfir-local-small : T1021.002, T1569.002
- lm-wmiexec-impacket / règles seules : T1047
- lm-wmiexec-impacket / dfir-local : T1047
- lm-wmiexec-impacket / dfir-local-small : T1047
- pe-uac-bypass-eventvwr / règles seules : T1548.002
- pe-uac-bypass-eventvwr / dfir-local : T1548.002
- pe-uac-bypass-eventvwr / dfir-local-small : T1548.002
- persist-accessibility-osk / règles seules : T1546.008
- persist-accessibility-osk / dfir-local : T1546.008
- persist-accessibility-osk / dfir-local-small : T1546.008
- persist-local-admin-account-sysmon / règles seules : T1098, T1136.001
- persist-local-admin-account-sysmon / dfir-local : T1098, T1136.001
- persist-local-admin-account-sysmon / dfir-local-small : T1098, T1136.001

## Lecture

- Verdicts exacts : 20 % pour les règles comme pour les deux modèles. Sur des attaques que les règles ne connaissent pas, aucun modèle n'arrive au verdict `malicious` par lui-même.
- Danger vu : 80 % pour le 14B et 70 % pour le 7B, contre 40 % pour les règles seules. Le 14B signale comme `suspicious` quatre attaques que les règles classaient `benign` (DCSync, regsvr32, wmiexec, porte dérobée osk.exe), le 7B trois. C'est l'apport réel du modèle : il double la part d'attaques repérées, alors que les critères de verdict lui demandent de répondre `benign` sans preuve.
- Techniques : F1 identique aux règles (0.20). Quand le modèle repère une attaque que les règles ont manquée, il ne cite pas la bonne technique ATT&CK. Il voit une anomalie sans savoir la nommer.
- Les manques restent ceux des règles : DCSync (4662), désactivation et contournement de l'UAC, regsvr32, wmiexec, PsExec, porte dérobée d'accessibilité, ajout aux Administrateurs vu par Sysmon. Ce sont des détections que les règles Sigma de la communauté couvrent déjà.
- Le 14B répond une fois `inconclusive`. Aucune fuite ; deux indicateurs non fondés sur 20 réponses.
