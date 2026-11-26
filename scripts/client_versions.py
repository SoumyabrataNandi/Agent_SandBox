"""Keep the client library versions equal to the sandboxd workspace version (FR-CL2.2).

    python scripts/client_versions.py          # check; exit 1 and list the differences
    python scripts/client_versions.py --set    # rewrite the clients to the workspace version

Standard library only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (file, regex whose group 1 is the version)
CLIENT_FILES = [
    ("clients/python/pyproject.toml", r'(?m)^version = "([^"]+)"'),
    ("clients/python/src/sandboxd_client/_client.py", r'(?m)^__version__ = "([^"]+)"'),
    ("clients/js/package.json", r'(?m)^  "version": "([^"]+)"'),
    ("clients/js/index.js", r'(?m)^export const VERSION = "([^"]+)"'),
]


def workspace_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'(?ms)^\[workspace\.package\].*?^version = "([^"]+)"', text)
    if not m:
        raise SystemExit("no [workspace.package] version in Cargo.toml")
    return m.group(1)


def main() -> int:
    want = workspace_version()
    set_mode = "--set" in sys.argv[1:]
    bad = []
    for rel, pattern in CLIENT_FILES:
        path = ROOT / rel
        raw = path.read_bytes().decode("utf-8")
        m = re.search(pattern, raw)
        if not m:
            bad.append(f"{rel}: version not found")
            continue
        if m.group(1) == want:
            continue
        if set_mode:
            raw = raw[: m.start(1)] + want + raw[m.end(1):]
            path.write_bytes(raw.encode("utf-8"))
            print(f"{rel}: {m.group(1)} -> {want}")
        else:
            bad.append(f"{rel}: {m.group(1)} (workspace {want})")
    if bad:
        print("client versions differ from the workspace version:\n  " + "\n  ".join(bad))
        print("fix with: python scripts/client_versions.py --set")
        return 1
    print(f"client versions: {want}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
