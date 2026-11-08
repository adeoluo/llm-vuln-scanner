"""Convert the downloaded datasets into the JSONL files the dataset probes read.

    uv run --group data python scripts/prepare_data.py --data ../.bench-data/llm-vuln-scanner/data

Tensor Trust files are already JSONL and are used as downloaded. The Gandalf splits are
merged into gandalf.jsonl (text, split) and the in-the-wild jailbreak snapshot becomes
wild_jailbreak.jsonl (prompt, platform, source); the probe itself drops templates without
a placeholder, longer than 6,000 characters or with explicit content.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyarrow.parquet as pq


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  {path.name}: {len(rows)} rows")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, type=Path)
    d = ap.parse_args().data
    gandalf = []
    for split in ("train", "validation", "test"):
        for r in pq.read_table(d / f"gandalf_{split}.parquet").to_pylist():
            gandalf.append({"text": r["text"], "split": split})
    write_jsonl(d / "gandalf.jsonl", gandalf)
    wild = [{"prompt": r["prompt"], "platform": r["platform"], "source": r["source"]}
            for r in pq.read_table(d / "wild_jailbreak_2023_12_25.parquet").to_pylist()]  # fmt: skip
    write_jsonl(d / "wild_jailbreak.jsonl", wild)
    for name in ("tt_hijacking.jsonl", "tt_extraction.jsonl"):
        with (d / name).open(encoding="utf-8") as f:
            print(f"  {name}: {sum(1 for line in f if line.strip())} rows")


if __name__ == "__main__":
    main()
