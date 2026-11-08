"""Write the technique list of a MITRE ATLAS data release for the taxonomy tests.

    uv run --with pyyaml python scripts/atlas_snapshot.py                 # downloads v2026.10
    uv run --with pyyaml python scripts/atlas_snapshot.py --yaml ATLAS-2026.10.yaml

Reads ``ATLAS-<version>.yaml`` (the asset attached to the atlas-data GitHub release) and
writes tests/data/atlas-<version>-techniques.json: the release version, its modified
date, the SHA-256 of the YAML file, and the identifier and name of every tactic and
technique. ``tests/test_taxonomy.py`` checks that every ATLAS identifier the probes cite
exists in that release under the same name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "https://github.com/mitre-atlas/atlas-data/releases/download/v{v}/ATLAS-{v}.yaml"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="2026.10")
    ap.add_argument("--yaml", default=None, help="local copy of the release YAML (default: download)")
    args = ap.parse_args()
    url = RELEASE.format(v=args.version)
    if args.yaml:
        raw = Path(args.yaml).read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as r:
            raw = r.read()
    data = yaml.safe_load(raw)
    collection = data["collection"]
    if str(collection["version"]) != args.version:
        raise SystemExit(f"file is ATLAS {collection['version']}, expected {args.version}")
    out = {
        "source": url,
        "version": str(collection["version"]),
        "format_version": str(data["format-version"]),
        "modified_date": str(collection["modified-date"]),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "tactics": {k: v["name"] for k, v in sorted(data["tactics"].items())},
        "techniques": {k: v["name"] for k, v in sorted(data["techniques"].items())},
    }
    path = ROOT / "tests" / "data" / f"atlas-{args.version}-techniques.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{path}: {len(out['tactics'])} tactics, {len(out['techniques'])} techniques")


if __name__ == "__main__":
    main()
