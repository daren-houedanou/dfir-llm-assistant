#!/usr/bin/env bash
# Download the public EVTX samples used by eval/public/ and convert them to evtx_dump JSONL.
#
# Dataset: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0, not redistributed here).
# Requires git and either `evtx_dump` (nix-forensics / `nix develop`) or `pip install evtx`.
set -euo pipefail
cd "$(dirname "$0")/.."
CACHE=${CACHE:-.cache/EVTX-ATTACK-SAMPLES}
if [ ! -d "$CACHE/.git" ]; then
  git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES "$CACHE"
fi
# eval/public: the set the rules were tuned on. eval/holdout: samples never looked at while writing rules.
for SET in public holdout; do
  OUT=data/$SET
  mkdir -p "$OUT"
  grep -v '^#' "eval/$SET/FILES.txt" | while IFS= read -r rel; do
    [ -n "$rel" ] && python3 scripts/evtx_to_jsonl.py "$OUT" "$CACHE/$rel"
  done
  echo "Converted files are in $OUT. Run: dfa eval eval/$SET -m dfir-local -r eval-$SET.md"
done
