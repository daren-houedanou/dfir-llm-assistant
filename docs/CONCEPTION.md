# Conception

Ce document explique les choix techniques de l'assistant, la façon dont il préserve la valeur probante d'une analyse, et ses limites connues.

## Choix techniques

| Choix | Raison |
|---|---|
| Règles déterministes avant le modèle | Les règles sont rapides, explicables et rejouables. Leurs résultats sont transmis au modèle comme preuves numérotées `[F#]`, ce qui réduit les hallucinations et le nombre de tokens. Le modèle apporte la synthèse, la corrélation et les réponses aux questions. |
| Passerelle LiteLLM | Une API unique compatible OpenAI pour tous les modèles. Le routage, les réessais, les fallbacks, les clés et les budgets sont gérés par la passerelle, pas par chaque client. Changer de modèle ne modifie pas le client. |
| Modèles locaux par défaut | Un dossier est confidentiel par défaut : seuls les alias `dfir-local*` sont autorisés. Le modèle par défaut est Qwen2.5 7B Instruct (bon en JSON pour sa taille), avec Llama 3.2 3B pour un poste sans GPU. |
| Contexte sous budget | Des milliers d'événements sont réduits à des statistiques, aux preuves `[F#]` (au plus 60 % du budget) et à une chronologie des événements notables : preuves, types rares, puis échantillon uniforme. |
| Vérification systématique | Schéma JSON avec un tour de réparation, identifiants ATT&CK vérifiés dans un catalogue local, indicateurs cherchés dans les artefacts bruts, requêtes Sigma et jq vérifiées, requête jq exécutée sur les preuves. |
| Critères de verdict explicites | Le prompt lie le verdict à la gravité des preuves : `malicious` si une preuve HIGH ou CRITICAL montre une action d'attaquant, `suspicious` pour des preuves faibles, `benign` sans preuve. Sans ces critères, les modèles évalués répondaient « suspicious » à presque toutes les attaques. |
| Évaluation comparative | Chaque modèle est comparé à la référence « règles seules », sur des jeux distincts pour la mise au point (`eval/public`) et pour la mesure (`eval/holdout`). |
| Intégration Nix | `flake.nix` fournit le paquet, un shell de développement avec `evtx_dump` et un overlay pour ajouter l'assistant à un environnement nix-forensics. Le build Nix exécute les tests. |

## Valeur probante

Une analyse forensique doit être répétable (même analyste, mêmes outils, même résultat) et reproductible (un autre expert retrouve le même résultat), avec une traçabilité des preuves. C'est ce que décrivent les normes ISO/IEC 27037 (collecte et préservation) et ISO/IEC 27042 (analyse et interprétation).

Un LLM pose trois problèmes à cet égard : sa sortie n'est pas garantie identique d'une exécution à l'autre, en particulier avec une API cloud ; il peut inventer des faits ; son raisonnement ne peut pas être vérifié.

L'assistant le traite donc comme une aide à l'analyse, jamais comme une preuve :

- les constats sur lesquels repose un rapport viennent d'outils déterministes (parseurs, règles), rejouables à l'identique ;
- chaque affirmation du modèle doit renvoyer à une preuve (`[F#]` ou ligne de chronologie), et un indicateur absent des artefacts est signalé ;
- chaque appel est journalisé : empreinte SHA-256 des artefacts, requête exacte envoyée, modèle demandé et modèle servi, version de l'outil et du prompt, température 0, graine fixe, réponse brute et son empreinte ;
- les enregistrements du journal sont chaînés par hash : `dfa audit verify` détecte une modification, une insertion ou une suppression, ainsi qu'un artefact modifié depuis l'analyse ;
- `dfa audit replay` renvoie les requêtes enregistrées et compare les réponses. Lors de l'évaluation, deux sessions GPU distinctes ont donné des réponses identiques au token près ;
- chaque résumé rappelle à l'analyste de vérifier les affirmations avant de les reporter.

Le rapport final doit pouvoir être reconstitué sans le LLM. Le règlement européen sur l'IA classe à haut risque certains systèmes utilisés par les autorités répressives pour évaluer la fiabilité des preuves : un CERT d'entreprise n'en fait pas partie, mais la même exigence de transparence s'applique si un dossier est transmis à la justice.

## Confidentialité

Trois niveaux empêchent une fuite vers un modèle cloud :

| Niveau | Mécanisme |
|---|---|
| Client | Politique appliquée avant tout envoi : un alias cloud est refusé sans `--cloud`. Avec `--cloud`, le prompt est pseudonymisé (`HOST_1`, `USER_2`, `IP_PUB_3`) en gardant la distinction entre IP interne et externe, puis la réponse est restaurée. `--show-prompt` affiche ce qui est envoyé. |
| Passerelle | Profil air-gapped sans aucun modèle cloud, fallbacks qui ne franchissent pas la frontière local/cloud, journalisation des prompts désactivée, clés virtuelles par équipe limitées aux modèles locaux. |
| Réseau | Ollama sans accès Internet : réseau interne dans Docker Compose, NetworkPolicies en default-deny dans Kubernetes. Les modèles sont téléchargés par un conteneur ou un Job distinct. |

Le nombre de valeurs sensibles retrouvées dans les prompts envoyés au cloud est mesuré par `dfa eval` et doit rester à 0.

## Limites connues

- Les 14 règles écrites à la main généralisent mal : 100 % de verdicts justes sur le jeu de mise au point, 20 % sur le jeu `holdout`. L'étape suivante est d'exécuter les règles Sigma de la communauté (SigmaHQ), par exemple avec `sigma-cli`, et d'en faire des preuves `[F#]`.
- Avec les critères de verdict actuels, le modèle suit la gravité donnée par les règles et rattrape peu ce qu'elles ne détectent pas. Une piste est de l'autoriser à signaler une attaque à condition de citer la ligne de journal correspondante.
- Les modèles ne reprennent pas toujours toutes les techniques trouvées par les règles, et peuvent en lister même avec un verdict `benign`.
- La pseudonymisation repose sur des expressions régulières et sur les champs structurés : un nom d'hôte cité uniquement dans un texte libre peut lui échapper.
- Chaque essai d'évaluation a été exécuté une seule fois par modèle ; `dfa eval --repeat` permet de mesurer la variabilité.

## Pistes

- Exécution des règles Sigma et recherche dans le référentiel ATT&CK complet (STIX).
- Appels d'outils, pour que le modèle demande lui-même un artefact complémentaire (regipy, volatility3).
- Remplacement d'Ollama par vLLM pour le débit en production, autoscaling de la passerelle.
- Évaluation de la qualité des résumés par un modèle juge.
