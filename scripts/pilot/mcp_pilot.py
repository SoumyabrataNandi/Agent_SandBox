#!/usr/bin/env python3
"""MCP agent pilot for sandboxd (cycle 4, FR-PL1).

Drives `sandboxd mcp` over stdio the way an agent does: the real JSON-RPC handshake, then a
sequence of agent-shaped tool calls, each with explicit checks. Standard library only; run with
`python -I`. Exit status is non-zero if any check fails.

    python -I scripts/pilot/mcp_pilot.py --sandboxd target/release/sandboxd [--workdir DIR] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"

CSV = "region,product,units,price\n" + "\n".join(
    f"{r},{p},{u},{pr}"
    for r, p, u, pr in [
        ("north", "widget", 12, "2.50"),
        ("south", "widget", 7, "2.50"),
        ("north", "gadget", 3, "10.00"),
        ("east", "gadget", 9, "10.00"),
        ("south", "gizmo", 20, "1.25"),
        ("east", "widget", 4, "2.50"),
    ]
) + "\n"


class Fail(Exception):
    pass


class McpClient:
    """Newline-delimited JSON-RPC over the child's stdio (MCP stdio transport)."""

    def __init__(self, argv: list[str], env: dict[str, str], stderr_path: Path):
        self._stderr = open(stderr_path, "wb")
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr, env=env
        )
        self._next_id = 0
        self._msgs: queue.Queue = queue.Queue()
        self.notifications: list[dict] = []
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._msgs.put(json.loads(line))
            except json.JSONDecodeError:
                self._msgs.put({"_bad_line": line.decode("utf-8", "replace")})
        self._msgs.put(None)

    def send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg).encode() + b"\n")
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method: str, params: dict | None = None, timeout: float = 120) -> dict:
        self._next_id += 1
        rid = self._next_id
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Fail(f"{method}: no response within {timeout:.0f} s")
            try:
                msg = self._msgs.get(timeout=left)
            except queue.Empty:
                continue
            if msg is None:
                raise Fail(f"{method}: server closed stdout (exit code {self.proc.poll()})")
            if "_bad_line" in msg:
                raise Fail(f"non-JSON line on the protocol stream: {msg['_bad_line'][:200]!r}")
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                return msg
            if "method" in msg and "id" not in msg:
                self.notifications.append(msg)
            # Anything else (a server→client request) is unexpected for this pilot; ignore it.

    def call_tool(self, name: str, args: dict, *, progress: str | None = None, timeout: float = 900) -> dict:
        params: dict = {"name": name, "arguments": args}
        if progress:
            params["_meta"] = {"progressToken": progress}
        msg = self.request("tools/call", params, timeout=timeout)
        if "error" in msg:
            return {"_rpc_error": msg["error"]}
        return msg["result"]

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        self._stderr.close()


def texts(result: dict) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def resources(result: dict) -> list[dict]:
    return [c["resource"] for c in result.get("content", []) if c.get("type") == "resource"]


def sc(result: dict) -> dict:
    return result.get("structuredContent") or {}


def check(cond: bool, what: str, result: dict | None = None) -> None:
    if not cond:
        detail = ""
        if result is not None:
            detail = "\n      result: " + json.dumps(result)[:1500]
        raise Fail(what + detail)


# --------------------------------------------------------------------------------------------
# Scenarios. Each takes the client and raises Fail on the first failed check.


def s_handshake(c: McpClient, init: dict) -> str:
    info = init["result"]
    check("tools" in info.get("capabilities", {}), "server advertises tools", info)
    instr = info.get("instructions", "")
    check("standard library" in instr and "/out" in instr, "instructions explain stdlib-only and /out", info)
    tools = {t["name"]: t for t in c.request("tools/list")["result"]["tools"]}
    for name in ("run_code", "list_policies", "session_create", "session_close"):
        check(name in tools, f"tool {name} listed")
    props = tools["run_code"]["inputSchema"].get("properties", {})
    for p in ("language", "code", "files", "limits", "session_id"):
        check(p in props, f"run_code schema has `{p}`")
    return f"{len(tools)} tools, server {info.get('serverInfo', {}).get('name')} {info.get('serverInfo', {}).get('version')}"


def s_policies(c: McpClient) -> str:
    r = c.call_tool("list_policies", {})
    names = [p.get("name") for p in sc(r).get("policies", [])]
    check({"default", "notebook"} <= set(names), "policies default + notebook listed", r)
    check("notebook" in texts(r), "policy list readable as text", r)
    return ", ".join(names)


def s_csv(c: McpClient) -> str:
    code = r"""
import csv, json, statistics
from collections import defaultdict
rows = list(csv.DictReader(open('/in/sales.csv')))
rev = defaultdict(float)
for r in rows:
    rev[r['region']] += int(r['units']) * float(r['price'])
summary = {k: round(v, 2) for k, v in sorted(rev.items())}
print(json.dumps({'rows': len(rows), 'revenue': summary, 'median_units': statistics.median(int(r['units']) for r in rows)}))
with open('/out/report.md', 'w') as f:
    f.write('| region | revenue |\n|---|---|\n')
    for k, v in summary.items():
        f.write(f'| {k} | {v:.2f} |\n')
"""
    r = c.call_tool("run_code", {"language": "python", "code": code, "files": [{"name": "sales.csv", "content": CSV}]})
    check(not r.get("isError"), "CSV run succeeds", r)
    out = sc(r).get("stdout", "")
    data = json.loads(out.strip().splitlines()[-1])
    check(data == {"rows": 6, "revenue": {"east": 100.0, "north": 60.0, "south": 42.5}, "median_units": 8.0},
          "CSV aggregates are correct", r)
    res = resources(r)
    check(len(res) == 1 and res[0]["uri"].endswith("/out/report.md"), "/out/report.md returned as a resource", r)
    check("| north | 60.00 |" in res[0].get("text", ""), "artifact content is the report", r)
    return f"stdout + 1 artifact, {sc(r).get('timings', {}).get('total_ms')} ms"


def s_exception(c: McpClient) -> str:
    code = "def parse(x):\n    return int(x)\n\nvalues = ['1', '2', 'three']\nprint(sum(parse(v) for v in values))\n"
    r = c.call_tool("run_code", {"language": "python", "code": code})
    s = sc(r)
    check(s.get("exit_code") == 1, "uncaught exception → exit code 1", r)
    err = s.get("stderr", "")
    check("ValueError" in err and "three" in err, "traceback shows the ValueError", r)
    check('main.py", line 2' in err, "traceback names the user's line", r)
    # U5 design: the tool worked, the program failed. isError is reserved for service errors and
    # traps; the summary line tells the model the program failed.
    check(r.get("isError") is not True and "exit code 1" in texts(r), "summary says the program exited 1", r)
    return "traceback with user line; summary shows exit code 1"


def s_limit(c: McpClient) -> str:
    t0 = time.monotonic()
    r = c.call_tool("run_code", {"language": "python", "code": "while True:\n    pass\n", "limits": {"wall_clock": "1s"}})
    dt = time.monotonic() - t0
    s = sc(r)
    hit = " ".join(s.get("limits_hit", []))
    check(bool(hit), "a limit is reported", r)
    check(f"limits hit: {hit}" in texts(r), "the summary text names the limit", r)
    check(s.get("outcome") == "limit", "outcome is `limit`", r)
    check(dt < 10, f"run stopped promptly ({dt:.1f} s)", r)
    return f"{hit} after {dt:.1f} s"


def s_native(c: McpClient) -> str:
    r = c.call_tool("run_code", {"language": "python", "code": "import numpy as np\nprint(np.arange(3))\n"})
    blob = texts(r) + json.dumps(sc(r))
    check("UNSUPPORTED_NATIVE_EXTENSION" in blob, "numpy import → UNSUPPORTED_NATIVE_EXTENSION", r)
    check("standard library" in blob or "stdlib" in blob or "numpy" in blob, "the message tells the agent what to do", r)
    return (sc(r).get("error") or {}).get("message", "")[:80]


def s_js(c: McpClient) -> str:
    code = (
        "import * as std from 'qjs:std';\n"
        "const data = JSON.parse(std.loadFile('/in/points.json'));\n"
        "const total = data.reduce((a, d) => a + d.n * d.n, 0);\n"
        "console.log(JSON.stringify({ total, ok: data.every(d => d.n > 2) }));\n"
    )
    files = [{"name": "points.json", "content": '[{"n":3},{"n":4},{"n":5}]'}]
    r = c.call_tool("run_code", {"language": "javascript", "code": code, "files": files})
    check(not r.get("isError"), "JS run succeeds", r)
    check(json.loads(sc(r).get("stdout", "").strip()) == {"total": 50, "ok": True}, "JS result correct", r)
    return "ok"


def s_session(c: McpClient) -> str:
    r = c.call_tool("session_create", {"language": "python", "policy": "notebook"})
    check(not r.get("isError"), "session_create succeeds", r)
    sid = sc(r).get("session_id")
    check(bool(sid), "session_id returned", r)
    cells = [
        ("import json\nrows = [1, 2, 3]\nprint('cell1')", "cell1"),
        ("rows.append(4)\nopen('/work/state.json', 'w').write(json.dumps(rows))\nprint(len(rows))", "4"),
        ("print(json.loads(open('/work/state.json').read())[-1] * 10)", "40"),
    ]
    for i, (code, want) in enumerate(cells, 1):
        r = c.call_tool("run_code", {"language": "python", "code": code, "session_id": sid})
        check(not r.get("isError") and sc(r).get("stdout", "").strip() == want, f"session cell {i} prints {want}", r)
    r = c.call_tool("session_close", {"session_id": sid})
    check(not r.get("isError"), "session_close succeeds", r)
    r = c.call_tool("run_code", {"language": "python", "code": "print(rows)", "session_id": sid})
    check(r.get("isError") is True and "SESSION_NOT_FOUND" in texts(r), "a closed session → SESSION_NOT_FOUND", r)
    return "3 cells (globals, imports, /work), closed cleanly"


def s_progress(c: McpClient) -> str:
    before = len(c.notifications)
    code = "import time\nfor i in range(3):\n    print('tick', i, flush=True)\n    time.sleep(0.2)\n"
    r = c.call_tool("run_code", {"language": "python", "code": code}, progress="pilot-progress")
    check(not r.get("isError"), "streamed run succeeds", r)
    prog = [n for n in c.notifications[before:] if n.get("method") == "notifications/progress"
            and n.get("params", {}).get("progressToken") == "pilot-progress"]
    msgs = "".join(n["params"].get("message", "") for n in prog)
    check(len(prog) >= 1 and "tick 2" in msgs, f"progress notifications carry stdout ({len(prog)} received)", r)
    return f"{len(prog)} progress notifications"


def s_bad_input(c: McpClient) -> str:
    r = c.call_tool("run_code", {"language": "ruby", "code": "puts 1"})
    check(r.get("isError") is True or "_rpc_error" in r, "unknown language is rejected", r)
    r = c.call_tool("run_code", {"language": "python", "code": "print(1)", "policy": "nope"})
    check(r.get("isError") is True and "nope" in texts(r), "unknown policy is rejected and named", r)
    r = c.call_tool("run_code", {"language": "python", "code": "print('still alive')"})
    check(sc(r).get("stdout", "").strip() == "still alive", "server still usable afterwards", r)
    return "rejected cleanly; server still serving"


SCENARIOS = [
    ("policies", s_policies),
    ("csv-analysis", s_csv),
    ("exception", s_exception),
    ("wall-clock-limit", s_limit),
    ("native-extension", s_native),
    ("javascript", s_js),
    ("session", s_session),
    ("progress-stream", s_progress),
    ("bad-input", s_bad_input),
]


def write_config(work: Path, cache: Path) -> Path:
    pol = work / "policies"
    pol.mkdir(parents=True, exist_ok=True)
    (pol / "notebook.toml").write_text(
        'version = 1\nname = "notebook"\ndescription = "Pilot: sessions on"\n'
        '[limits]\nwall_clock = "10s"\n[session]\nenabled = true\nidle_ttl = "2m"\n',
        encoding="utf-8",
    )
    cfg = work / "sandboxd.toml"
    p = lambda x: x.as_posix()  # noqa: E731 - TOML strings with forward slashes work on every OS
    cfg.write_text(
        f'policy_dir = "{p(pol)}"\ncache_dir = "{p(cache)}"\nwork_dir = "{p(work / "runs")}"\n'
        f'[audit]\nsink = "file"\npath = "{p(work / "audit.jsonl")}"\n',
        encoding="utf-8",
    )
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandboxd", required=True, help="path to the sandboxd binary")
    ap.add_argument("--workdir", help="scratch directory (default: a new temp dir, removed afterwards)")
    ap.add_argument("--cache-dir", help="compile/snapshot cache (default: <workdir>/cache)")
    ap.add_argument("--startup-timeout", type=float, default=900, help="seconds for initialize")
    ap.add_argument("--max-initialize", type=float, default=10,
                    help="fail if initialize takes longer (FR-ST1: it must not wait for the cache build)")
    ap.add_argument("--json", help="write results as JSON here")
    a = ap.parse_args()

    exe = shutil.which(a.sandboxd) or a.sandboxd
    if not Path(exe).is_file():
        print(f"sandboxd binary not found: {a.sandboxd}", file=sys.stderr)
        return 2
    own_dir = a.workdir is None
    work = Path(a.workdir or tempfile.mkdtemp(prefix="sandboxd-pilot-")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    cache = Path(a.cache_dir).resolve() if a.cache_dir else work / "cache"
    cfg = write_config(work, cache)

    env = {k: v for k, v in os.environ.items() if not k.startswith("SANDBOXD_")}
    env["SANDBOXD_CONFIG"] = str(cfg)
    stderr_log = work / "sandboxd-stderr.log"
    c = McpClient([exe, "mcp"], env, stderr_log)

    results: list[dict] = []
    ok = True
    try:
        t0 = time.monotonic()
        init = c.request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
             "clientInfo": {"name": "sandboxd-mcp-pilot", "version": "1"}},
            timeout=a.startup_timeout,
        )
        if "error" in init:
            raise Fail(f"initialize failed: {init['error']}")
        c.notify("notifications/initialized")
        startup = time.monotonic() - t0
        # FR-ST1 (cycle 5): the handshake is answered before the sandbox is built.
        results.append({"scenario": "fast-initialize", "ok": startup <= a.max_initialize, "ms": round(startup * 1000),
                        "note": f"initialize answered in {startup:.2f} s (limit {a.max_initialize:.0f} s)"})
        ok = ok and startup <= a.max_initialize
        runs: list[tuple[str, object]] = [("handshake", lambda cl: s_handshake(cl, init))] + SCENARIOS
        for name, fn in runs:
            t = time.monotonic()
            try:
                note = fn(c)
                results.append({"scenario": name, "ok": True, "ms": round((time.monotonic() - t) * 1000), "note": note})
            except Fail as e:
                ok = False
                results.append({"scenario": name, "ok": False, "ms": round((time.monotonic() - t) * 1000), "note": str(e)})
            except Exception as e:  # a harness bug or a malformed reply: still report it as a failure
                ok = False
                results.append({"scenario": name, "ok": False, "ms": round((time.monotonic() - t) * 1000),
                                 "note": f"{type(e).__name__}: {e}"})
    except Fail as e:
        ok = False
        startup = None
        results.append({"scenario": "startup", "ok": False, "ms": 0, "note": str(e)})
    finally:
        c.close()

    width = max(len(r["scenario"]) for r in results)
    print(f"sandboxd MCP pilot: {exe}")
    if startup is not None:
        print(f"initialize answered: {startup:.2f} s; the first tool call includes the cache build on a cold cache")
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"  {mark}  {r['scenario']:<{width}}  {r['ms']:>6} ms  {r['note']}")
    print(f"{sum(r['ok'] for r in results)}/{len(results)} passed")
    if not ok:
        tail = stderr_log.read_text("utf-8", "replace")[-3000:] if stderr_log.exists() else ""
        if tail:
            print("--- sandboxd stderr (tail) ---\n" + tail)
    if a.json:
        Path(a.json).write_text(json.dumps({"ok": ok, "startup_s": startup, "results": results}, indent=2), encoding="utf-8")
    if own_dir:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
