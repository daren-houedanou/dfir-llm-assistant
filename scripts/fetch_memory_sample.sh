#!/usr/bin/env bash
# Télécharge une image mémoire publique d'une machine infectée et l'analyse avec Volatility 3.
#
# Image par défaut : Cridex (cheval de Troie bancaire), Windows XP SP2 x86, publiée par
# SemperSecurus et listée dans les échantillons de la Volatility Foundation. Les sorties JSON des
# plugins sont écrites dans data/memory/cridex, lues ensuite par eval/memory/cridex.yaml.
# Autre image : MEMORY_URL=<lien vers un .zip ou un fichier mémoire> bash scripts/fetch_memory_sample.sh
# Image déjà présente (par exemple un jeu de données Kaggle) : MEMORY_FILE=<chemin> bash scripts/fetch_memory_sample.sh
set -euo pipefail

# Le site d'origine ne répond plus : la copie de la Wayback Machine est essayée ensuite.
ORIGIN=http://files.sempersecurus.org/dumps/cridex_memdump.zip
URLS=${MEMORY_URL:-"$ORIGIN https://web.archive.org/web/2020id_/$ORIGIN"}
CACHE=${CACHE:-.cache/memory}
OUT=${OUT:-data/memory/cridex}
mkdir -p "$CACHE" "$OUT"

IMG=${MEMORY_FILE:-$(find "$CACHE" -maxdepth 2 -type f \( -name '*.vmem' -o -name '*.raw' -o -name '*.mem' -o -name '*.img' \) | head -1)}
if [ -z "$IMG" ]; then
  ok=
  for url in $URLS; do
    echo "Téléchargement : $url"
    if curl -fL --retry 2 -o "$CACHE/sample.download" "$url"; then ok=1; break; fi
  done
  [ -n "$ok" ] || { echo "Aucun lien n'a fonctionné. Indiquer MEMORY_URL ou MEMORY_FILE." >&2; exit 1; }
  if unzip -tq "$CACHE/sample.download" >/dev/null 2>&1; then
    unzip -o -q "$CACHE/sample.download" -d "$CACHE"
    rm "$CACHE/sample.download"
  else
    mv "$CACHE/sample.download" "$CACHE/sample.raw"
  fi
  IMG=$(find "$CACHE" -maxdepth 2 -type f \( -name '*.vmem' -o -name '*.raw' -o -name '*.mem' -o -name '*.img' \) | head -1)
fi
echo "Image : $IMG ($(du -h "$IMG" | cut -f1))"

command -v vol >/dev/null || pip install -q volatility3==2.11.0

run() {
  local plugin=$1
  if vol -q -r json -f "$IMG" "windows.$plugin" >"$OUT/windows.$plugin.json" 2>"$CACHE/windows.$plugin.err" &&
    python3 -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1])) else 1)' "$OUT/windows.$plugin.json"; then
    echo "windows.$plugin : OK"
  else
    echo "windows.$plugin : aucun résultat (détail dans $CACHE/windows.$plugin.err)"
    rm -f "$OUT/windows.$plugin.json"
    return 1
  fi
}

# Volatility télécharge les symboles du noyau Windows au premier passage. S'il n'y parvient pas,
# on installe le paquet de symboles de la Volatility Foundation puis on réessaie.
if ! run pslist; then
  SYMBOLS=$(python3 -c 'import os, volatility3; print(os.path.join(os.path.dirname(volatility3.__file__), "symbols"))')
  curl -fL --retry 3 -o "$CACHE/windows.zip" https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
  cp "$CACHE/windows.zip" "$SYMBOLS/"
  run pslist
fi
# netscan ne fonctionne qu'à partir de Windows Vista : son échec sur Windows XP est normal.
for plugin in cmdline netscan malfind; do
  run "$plugin" || true
done
echo "Sorties Volatility dans $OUT. Lancer : dfa triage $OUT"
