"""Run a command against a throwaway `sandboxd serve` (cycle 6, FR-CL1.7).

    python clients/testserver.py --sandboxd target/debug/sandboxd -- python -m unittest ...

Starts the server on a free loopback port with a fresh token and two policies (`default`, and
`notebook` with sessions on), waits for /healthz, runs the command with SANDBOXD_URL and
SANDBOXD_TOKEN set, then stops the server. Exits with the command's exit code. The cache
directory can be shared between runs with --cache-dir (the first start builds it).
Standard library only.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sandboxd", required=True, help="path to the sandboxd binary")
    ap.add_argument("--cache-dir", help="reuse this cache directory (default: a temporary one)")
    ap.add_argument("--ready-timeout", type=float, default=600.0)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        ap.error("no command given (put it after --)")

    exe = str(Path(a.sandboxd).resolve())
    out = subprocess.run([exe, "token", "new", "--name", "clients"], check=True,
                         capture_output=True, text=True).stdout
    token = out.splitlines()[1].strip()
    sha = re.search(r'sha256 = "([0-9a-f]{64})"', out).group(1)

    work = Path(tempfile.mkdtemp(prefix="sandboxd-clients-"))
    port = free_port()
    pol = work / "policies"
    pol.mkdir()
    (pol / "notebook.toml").write_text(
        'version = 1\nname = "notebook"\ndescription = "Client tests: sessions on"\n'
        '[limits]\nwall_clock = "10s"\n[session]\nenabled = true\nidle_ttl = "2m"\n',
        encoding="utf-8",
    )
    cache = Path(a.cache_dir).resolve() if a.cache_dir else work / "cache"
    q = lambda p: str(p).replace("\\", "/")  # noqa: E731 (TOML-safe paths on Windows)
    (work / "sandboxd.toml").write_text(
        f'policy_dir = "{q(pol)}"\ncache_dir = "{q(cache)}"\nwork_dir = "{q(work / "work")}"\n'
        f'[server]\nlisten = "127.0.0.1:{port}"\n'
        f'[auth]\ntokens = [ {{ name = "clients", sha256 = "{sha}" }} ]\n'
        f'[audit]\nsink = "file"\npath = "{q(work / "audit.jsonl")}"\n',
        encoding="utf-8",
    )
    log = open(work / "server.log", "wb")
    server = subprocess.Popen([exe, "serve", "--config", str(work / "sandboxd.toml")],
                              stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + a.ready_timeout
        while True:
            if server.poll() is not None:
                raise SystemExit(f"sandboxd exited during start-up:\n{(work / 'server.log').read_text(errors='replace')}")
            try:
                with urllib.request.urlopen(url + "/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise SystemExit("sandboxd was not ready in time")
                time.sleep(0.5)
        print(f"testserver: sandboxd ready at {url}", flush=True)
        env = dict(os.environ, SANDBOXD_URL=url, SANDBOXD_TOKEN=token)
        return subprocess.call(cmd, env=env)
    finally:
        server.terminate()
        try:
            server.wait(timeout=20)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
