"""Download and cache real-world IOC data for test fixtures.

Run once before executing real-world tests:
    python -m tests.fixtures.download
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

# ESET malware-ioc: families with consistent samples.{md5,sha1,sha256} files
ESET_BASE = "https://raw.githubusercontent.com/eset/malware-ioc/master"
ESET_FAMILIES = [
    "emotet",
    "asyncrat",
    "danabot",
    "glupteba",
    "lummastealer",
    "redline",
    "turla",
    "gamaredon",
    "nukesped_lazarus",
    "kobalos",
]
HASH_TYPES = ("md5", "sha1", "sha256")

# bnsapa/cybersecurity-ner parquet files (HuggingFace)
NER_BASE = "https://huggingface.co/datasets/bnsapa/cybersecurity-ner/resolve/main/data"
NER_FILES = (
    "train-00000-of-00001.parquet",
    "test-00000-of-00001.parquet",
    "validation-00000-of-00001.parquet",
)


def _fetch(url: str, dest: Path) -> bool:
    if dest.exists():
        print(f"  cached   {dest.name}")
        return True
    print(f"  fetching {dest.name} ...", end=" ", flush=True)
    try:
        urllib.request.urlretrieve(url, dest)
        print("ok")
        return True
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code} — skipped")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}", file=sys.stderr)
        return False


def main() -> None:
    eset_dir = DATA_DIR / "eset"
    eset_dir.mkdir(parents=True, exist_ok=True)
    ner_dir = DATA_DIR / "ner"
    ner_dir.mkdir(parents=True, exist_ok=True)

    print("=== ESET malware hash files ===")
    for family in ESET_FAMILIES:
        for hash_type in HASH_TYPES:
            url = f"{ESET_BASE}/{family}/samples.{hash_type}"
            _fetch(url, eset_dir / f"{family}_{hash_type}.txt")

    print("\n=== Cybersecurity NER dataset (bnsapa/cybersecurity-ner) ===")
    for filename in NER_FILES:
        _fetch(f"{NER_BASE}/{filename}?download=true", ner_dir / filename)

    print("\nDone. Run real-world tests with:")
    print("  pytest tests/test_realworld_hashes.py tests/test_realworld_prose.py -v")


if __name__ == "__main__":
    main()
