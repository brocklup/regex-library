"""Real-world hash pattern tests using ESET malware-ioc samples.

Requires data to be downloaded first:
    python -m tests.fixtures.download
"""

import re
from pathlib import Path

import pytest

import patterns

ESET_DIR = Path(__file__).parent / "fixtures" / "data" / "eset"
_SKIP = pytest.mark.skipif(
    not ESET_DIR.exists() or not any(ESET_DIR.iterdir()) if ESET_DIR.exists() else True,
    reason="ESET data not downloaded — run: python -m tests.fixtures.download",
)


def _load(hash_type: str) -> list[str]:
    return [
        line.strip()
        for f in sorted(ESET_DIR.glob(f"*_{hash_type}.txt"))
        for line in f.read_text().splitlines()
        if line.strip()
    ]


def _assert_coverage(pattern: str, hashes: list[str], label: str) -> None:
    if not hashes:
        pytest.skip(f"No {label} hashes loaded from fixtures")
    misses = [h for h in hashes if not re.search(pattern, h)]
    families_repr = ", ".join(
        f.stem.removesuffix(f"_{label.lower().replace('-', '')}")
        for f in sorted(ESET_DIR.glob(f"*_{label.lower().replace('-', '')}.txt"))
    )
    assert not misses, (
        f"{len(misses)}/{len(hashes)} real {label} hashes not matched"
        f" (families: {families_repr}):\n"
        + "\n".join(f"  {h}" for h in misses[:10])
    )


@_SKIP
def test_sha256_pattern_on_real_hashes() -> None:
    """SHA-256 pattern matches every real malware SHA-256 hash from ESET."""
    _assert_coverage(patterns.HASH["sha256"], _load("sha256"), "SHA-256")


@_SKIP
def test_sha1_pattern_on_real_hashes() -> None:
    """SHA-1 pattern matches every real malware SHA-1 hash from ESET."""
    _assert_coverage(patterns.HASH["sha1"], _load("sha1"), "SHA-1")


@_SKIP
def test_md5_pattern_on_real_hashes() -> None:
    """MD5 pattern matches every real malware MD5 hash from ESET."""
    _assert_coverage(patterns.HASH["md5"], _load("md5"), "MD5")


@_SKIP
def test_combined_pattern_covers_all_hash_types() -> None:
    """Combined auto-detect pattern matches hashes of all three types."""
    all_hashes = [
        (h, label)
        for label, hash_type in (("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5"))
        for h in _load(hash_type)
    ]
    if not all_hashes:
        pytest.skip("No hash fixtures found")
    misses = [(h, t) for h, t in all_hashes if not re.search(patterns.HASH["combined"], h)]
    assert not misses, (
        f"{len(misses)}/{len(all_hashes)} hashes not matched by combined pattern:\n"
        + "\n".join(f"  [{t}] {h}" for h, t in misses[:10])
    )


@_SKIP
def test_fixture_summary(capsys: pytest.CaptureFixture[str]) -> None:
    """Print a summary of loaded fixture data (always passes)."""
    rows = []
    for hash_type in ("md5", "sha1", "sha256"):
        files = sorted(ESET_DIR.glob(f"*_{hash_type}.txt"))
        total = sum(
            sum(1 for line in f.read_text().splitlines() if line.strip()) for f in files
        )
        rows.append(f"  {hash_type:>6}: {total:>4} hashes from {len(files)} families")
    with capsys.disabled():
        print("\nESET fixture summary:")
        print("\n".join(rows))
