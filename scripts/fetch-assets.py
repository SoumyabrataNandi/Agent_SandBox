#!/usr/bin/env python3
"""Download the pinned guest interpreters listed in assets/manifest.toml into assets/vendor/.

Standard library only (Python >= 3.11 for tomllib). Each file is downloaded to a temporary
name, verified against its pinned SHA-256, and only then moved into place, so a partial or
tampered download never sits at the final path.

Usage:
    python scripts/fetch-assets.py           # fetch anything missing or mismatched
    python scripts/fetch-assets.py --check   # verify only, never download (exit 1 on problems)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "assets" / "manifest.toml"
VENDOR = Path(os.environ.get("SANDBOXD_ASSETS_DIR", ROOT / "assets" / "vendor"))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(url: str, dest: Path, expected: str) -> None:
    tmp = dest.with_suffix(dest.suffix + ".part")
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as res, tmp.open("wb") as out:
        for block in iter(lambda: res.read(1 << 20), b""):
            h.update(block)
            out.write(block)
    actual = h.hexdigest()
    if actual != expected:
        tmp.unlink(missing_ok=True)
        sys.exit(f"SHA-256 mismatch for {url}\n  expected {expected}\n  actual   {actual}")
    tmp.replace(dest)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify only; do not download")
    args = ap.parse_args()

    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    VENDOR.mkdir(parents=True, exist_ok=True)
    problems = 0

    for name, asset in manifest.items():
        dest = VENDOR / asset["file"]
        expected = asset["sha256"].lower()
        if dest.exists() and sha256_of(dest) == expected:
            print(f"[ok]      {name:<11} {asset['file']}")
            continue
        if args.check:
            print(f"[missing] {name:<11} {asset['file']}" if not dest.exists() else f"[BAD]     {name:<11} {asset['file']} (hash mismatch)")
            problems += 1
            continue
        print(f"[fetch]   {name:<11} {asset['url']}")
        fetch(asset["url"], dest, expected)
        print(f"[ok]      {name:<11} {asset['file']}")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
