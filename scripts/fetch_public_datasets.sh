#!/usr/bin/env bash
# Télécharge les enregistrements EVTX publics utilisés par eval/public et eval/holdout, et les convertit au format JSONL d'evtx_dump.
#
# Jeu de données : https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0, non redistribué ici).
# Nécessite git, et soit `evtx_dump` (nix-forensics ou `nix develop`), soit `pip install evtx`.
set -euo pipefail
cd "$(dirname "$0")/.."
CACHE=${CACHE:-.cache/EVTX-ATTACK-SAMPLES}
if [ ! -d "$CACHE/.git" ]; then
  git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES "$CACHE"
fi
# eval/public : jeu de mise au point des règles. eval/holdout : enregistrements jamais regardés pour écrire les règles.
for SET in public holdout; do
  OUT=data/$SET
  mkdir -p "$OUT"
  grep -v '^#' "eval/$SET/FILES.txt" | while IFS= read -r rel; do
    [ -n "$rel" ] && python3 scripts/evtx_to_jsonl.py "$OUT" "$CACHE/$rel"
  done
  echo "Fichiers convertis dans $OUT. Lancer : dfa eval eval/$SET -m dfir-local -r eval-$SET.md"
done
