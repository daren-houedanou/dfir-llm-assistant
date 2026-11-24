# Jeu synthétique : référence règles seules

Résultat des règles seules, sans modèle, sur les 4 scénarios synthétiques.

| scénario | modèle | verdict | ATT&CK P | ATT&CK R | R parent | F1 | IOC R | Q/R | IOC non fondés | fuites | latence | tokens |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| benign-admin-day | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| linux-ssh-compromise | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 80% | 0% | 0 | 0 | 0.0s | 0 |
| network-c2-exfil | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 100% | 0 | 0 | 0.0s | 0 |
| win-rdp-intrusion | règles seules | ✅ | 100% | 100% | 100% | 1.00 | 100% | 50% | 0 | 0 | 0.0s | 0 |

## Synthèse par modèle

| modèle | essais | verdicts justes | F1 moyen | IOC R moyen | Q/R moyen | fuites | latence médiane |
|---|---|---|---|---|---|---|---|
| règles seules | 4 | 100% | 1.00 | 95% | 62% | 0 | 0.0s |
