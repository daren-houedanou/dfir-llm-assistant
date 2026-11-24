#!/usr/bin/env python3
"""Convert .evtx files to the JSONL layout of ``evtx_dump -o jsonl``.

Uses ``evtx_dump`` when it is on PATH (nix-forensics shell), otherwise the ``evtx``
Python bindings (same Rust parser): ``pip install evtx``.

    python scripts/evtx_to_jsonl.py OUT_DIR file1.evtx [file2.evtx ...]
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def convert(src: Path, out_dir: Path) -> Path:
    dst = out_dir / (src.stem + ".jsonl")
    exe = shutil.which("evtx_dump")
    with dst.open("w") as handle:
        if exe:
            subprocess.run([exe, "-o", "jsonl", str(src)], stdout=handle, check=True)
        else:
            from evtx import PyEvtxParser  # type: ignore[import-not-found]

            for record in PyEvtxParser(str(src)).records_json():
                handle.write(json.dumps(json.loads(record["data"])) + "\n")
    return dst


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for arg in sys.argv[2:]:
        print(convert(Path(arg), out))
