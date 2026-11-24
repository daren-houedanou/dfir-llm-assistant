# Résultats d'évaluation

| Fichier | Contenu |
|---|---|
| [synthetique-regles-seules.md](synthetique-regles-seules.md) | Référence règles seules sur le jeu synthétique |
| [public-regles-seules.md](public-regles-seules.md) | Référence règles seules sur le jeu public, avant l'essai 3 |
| [essai1-synthetique-kaggle-t4.md](essai1-synthetique-kaggle-t4.md) | Essai 1, jeu synthétique : règles seules, Qwen2.5 14B et 7B |
| [essai1-public-kaggle-t4.md](essai1-public-kaggle-t4.md) | Essai 1, jeu public |
| [essai2-criteres-verdict-kaggle-t4.md](essai2-criteres-verdict-kaggle-t4.md) | Essai 2 : critères de verdict ajoutés au prompt |
| [essai3-regles-detection-kaggle-t4.md](essai3-regles-detection-kaggle-t4.md) | Essai 3 : nouvelles règles de détection |
| [holdout-regles-seules.md](holdout-regles-seules.md) | Référence règles seules sur le jeu holdout, jamais utilisé pour écrire les règles |
| [essai4-holdout-kaggle-t4.md](essai4-holdout-kaggle-t4.md) | Essai 4, jeu holdout : règles seules, Qwen2.5 14B et 7B |
| [essai5-memoire-cridex-kaggle-t4.md](essai5-memoire-cridex-kaggle-t4.md) | Essai 5 : analyse mémoire sur une image réelle infectée par Cridex |

## Colonnes des tableaux

| Colonne | Signification |
|---|---|
| verdict | Verdict donné, compté juste s'il est identique au verdict attendu |
| danger vu | Verdict `suspicious` ou `malicious` sur une attaque, `benign` sur une activité normale |
| ATT&CK P, ATT&CK R | Précision et rappel des techniques ATT&CK citées |
| R parent | Rappel en ne gardant que la technique parente (T1059 pour T1059.001) |
| F1 | Moyenne harmonique de la précision et du rappel ATT&CK |
| IOC R | Part des indicateurs attendus retrouvés |
| Q/R | Part des questions de l'analyste correctement répondues |
| IOC non fondés | Indicateurs cités par le modèle mais absents des artefacts |
| fuites | Valeurs sensibles retrouvées dans un prompt envoyé au cloud |
| latence, tokens | Temps de réponse et tokens consommés par le modèle |

Les verdicts (`malicious`, `suspicious`, `benign`) et les noms de scénarios sont laissés tels que l'outil les produit.
