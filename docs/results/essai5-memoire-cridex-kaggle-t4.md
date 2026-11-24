# Essai 5 : analyse mémoire sur une image réelle (Cridex)

Image mémoire d'un poste Windows XP SP2 infecté par Cridex, cheval de Troie bancaire qui s'injecte dans `explorer.exe` et `reader_sl.exe` (image SemperSecurus, listée par la Volatility Foundation, récupérée via la Wayback Machine). Volatility 3 (version 2.11.0 ; `pslist`, `cmdline`, `malfind` ; `netscan` ne fonctionne pas sous Windows XP), puis `dfa eval eval/memory`. Kaggle T4, Qwen2.5 14B (`dfir-local`) et 7B (`dfir-local-small`), mêmes prompt et réglages qu'aux essais précédents. Un seul essai par modèle.

## Premier passage : deux erreurs des règles mémoire

`dfa triage` sur les 48 événements extraits :

| Gravité | Preuve | ATT&CK |
|---|---|---|
| high | `services.exe` et `lsass.exe` lancés par `winlogon.exe` au lieu de `wininit.exe` | T1036.005 |
| medium | 12 zones mémoire exécutables et inscriptibles dans `csrss.exe`, `explorer.exe`, `reader_sl.exe`, `winlogon.exe` | T1055 |

| modèle | verdict | danger vu | ATT&CK P | ATT&CK R | F1 | IOC R | latence | tokens |
|---|---|---|---|---|---|---|---|---|
| règles seules | ✅ malicious | ✅ | 50% | 100% | 0.67 | 100% | 0.0s | 0 |
| dfir-local | ❌ suspicious | ✅ | 50% | 100% | 0.67 | 0% | 43.3s | 3360 |
| dfir-local-small | ❌ suspicious | ✅ | 50% | 100% | 0.67 | 100% | 21.9s | 3361 |

Causes :

- **Fausse alerte d'usurpation** : la règle supposait Windows Vista ou plus récent. Sous Windows XP, `wininit.exe` n'existe pas et `winlogon.exe` lance `services.exe` et `lsass.exe`.
- **Injection sous-estimée** : le rendu JSON de Volatility 3 entoure le dump hexadécimal de guillemets et le fait commencer par un saut de ligne. L'en-tête `MZ` d'un exécutable injecté n'était donc pas reconnu, et la preuve restait à la gravité medium. Le scénario synthétique ne reproduisait pas ce format.

## Second passage, après correction

`dfa triage` : une seule preuve, **high**, T1055 : 12 zones exécutables et inscriptibles, dont 2 commencent par un en-tête `MZ` (un exécutable entier chargé en mémoire sans fichier sur le disque).

| modèle | verdict | danger vu | ATT&CK P | ATT&CK R | F1 | IOC R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|
| règles seules | ✅ malicious | ✅ | 100% | 100% | 1.00 | 100% | 0 | 0 | 0.0s | 0 |
| dfir-local | ✅ malicious | ✅ | 100% | 100% | 1.00 | 100% | 0 | 0 | 29.4s | 2973 |
| dfir-local-small | ✅ malicious | ✅ | 100% | 100% | 1.00 | 100% | 0 | 0 | 20.3s | 3084 |

## Lecture

- Sur une vraie machine infectée, la chaîne complète fonctionne : Volatility 3, parseur, règles, puis modèle. L'injection de Cridex est trouvée, le verdict est juste et les deux modèles citent `reader_sl.exe`.
- Le test réel a révélé deux erreurs que le scénario synthétique ne pouvait pas montrer, car il avait été écrit avec les mêmes hypothèses que les règles. C'est la même leçon que le jeu `holdout` : une règle doit être validée sur des données qu'on n'a pas fabriquées soi-même.
- Au premier passage, avec une seule preuve medium, les modèles ont répondu `suspicious` : ils suivent la gravité des règles, comme sur les autres jeux.
- Les zones exécutables et inscriptibles de `csrss.exe` et `winlogon.exe` sont courantes sous Windows XP. Elles restent dans la preuve mais ne suffisent pas à la classer high : c'est l'en-tête `MZ` qui fait la différence.
- Limites : une seule image, sous Windows XP, sans analyse réseau (`netscan` n'existe pas pour cette version). Un seul essai par modèle.
