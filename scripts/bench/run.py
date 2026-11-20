#!/usr/bin/env python3
"""sandboxd benchmark harness (cycle 3, C3-U5; FR-B1, ADR-C3-6).

Measures sandboxd against Docker (and gVisor when present) and writes one JSON results file.
`render.py` turns that file into docs/BENCHMARKS.md, so published numbers are never typed by hand.

    python -I scripts/bench/run.py --sandboxd target/release/sandboxd --out bench-results.json

Standard library only. Comparators that are not available (no Docker, no runsc, no /proc for RSS)
are recorded under "skipped" with the reason, never silently dropped.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import http.client
import io
import json
import math
import os
import platform
import random
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = 1
PY_IMAGE = "python:3.15-slim"
JS_IMAGE = "node:22-slim"

HELLO_PY = "print(1)\n"
HELLO_JS = "console.log(1)\n"
# The realistic workload: parse a ~1 MiB CSV and aggregate it into JSON (B1.1).
CSV_PY = """\
import csv, json, sys
path = sys.argv[1] if len(sys.argv) > 1 else "/in/data.csv"
totals = {}
with open(path, newline="") as f:
    for row in csv.DictReader(f):
        t = totals.setdefault(row["category"], [0, 0.0])
        t[0] += 1
        t[1] += float(row["amount"])
out = {k: {"count": c, "sum": round(s, 2), "mean": round(s / c, 4)} for k, (c, s) in sorted(totals.items())}
print(json.dumps(out, sort_keys=True))
"""
# A live interpreter that does nothing: memory per sandbox.
SLEEP_PY = "import time\ntime.sleep({secs})\nprint(1)\n"


@dataclass(frozen=True)
class Scenario:
    name: str
    language: str  # python | javascript
    file: str
    code: str
    expect: str
    uses_input: bool = False


def make_csv(target_bytes: int = 1 << 20, seed: int = 42) -> str:
    rng = random.Random(seed)
    cats = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "category", "amount", "ts"])
    i = 0
    while buf.tell() < target_bytes:
        w.writerow([i, rng.choice(cats), f"{rng.uniform(0, 1000):.2f}", 1_700_000_000 + i * 37])
        i += 1
    return buf.getvalue()


def expected_csv_output(data_path: Path) -> str:
    """Run the workload on the host interpreter: the sandboxes must print the same line."""
    out = subprocess.run(
        [sys.executable, "-I", "-c", CSV_PY, str(data_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def percentile(xs: list[float], p: float) -> float:
    """Nearest-rank percentile of a non-empty list."""
    s = sorted(xs)
    k = max(0, math.ceil(p / 100 * len(s)) - 1)
    return s[k]


def latency_stats(ns: list[int]) -> dict:
    ms = [x / 1e6 for x in ns]
    return {
        "n": len(ms),
        "p50_ms": round(percentile(ms, 50), 3),
        "p95_ms": round(percentile(ms, 95), 3),
        "p99_ms": round(percentile(ms, 99), 3),
        "mean_ms": round(sum(ms) / len(ms), 3),
        "min_ms": round(min(ms), 3),
        "max_ms": round(max(ms), 3),
    }


def log(msg: str) -> None:
    print(f"[bench {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(cmd: list[str], timeout: float = 120) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True).stdout


def rss_mib(pid: int) -> float | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        return None
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RunError(Exception):
    pass


def check_output(scn_expect: str, got: str) -> None:
    if got != scn_expect:
        raise RunError(f"unexpected output {got[:200]!r} (want {scn_expect[:200]!r})")


# --------------------------------------------------------------------------------------------
# Systems under test
# --------------------------------------------------------------------------------------------


class System:
    name = "?"
    kind = "?"

    def supports(self, scn: Scenario) -> bool:
        return True

    def run(self, scn: Scenario) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SandboxdCli(System):
    """One `sandboxd run` process per execution: the cold path."""

    kind = "sandboxd"

    def __init__(self, ws: "Workspace"):
        self.name = "sandboxd-cli"
        self.ws = ws

    def run(self, scn: Scenario) -> None:
        cmd = [str(self.ws.bin), "run", "--config", str(self.ws.config("cli")), str(self.ws.progs / scn.file)]
        if scn.uses_input:
            cmd += ["--input", str(self.ws.data / "data.csv")]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=self.ws.root)
        if p.returncode != 0:
            raise RunError(f"exit {p.returncode}: {p.stderr[-300:]}")
        check_output(scn.expect, p.stdout)


class Http:
    """Keep-alive JSON client, one connection per thread."""

    def __init__(self, port: int, token: str):
        self.port = port
        self.token = token
        self.local = threading.local()

    def _conn(self) -> http.client.HTTPConnection:
        c = getattr(self.local, "c", None)
        if c is None:
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
            self.local.c = c
        return c

    def call(self, method: str, path: str, obj: object | None = None) -> tuple[int, object]:
        body = None if obj is None else json.dumps(obj).encode()
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in (0, 1):
            c = self._conn()
            try:
                c.request(method, path, body=body, headers=headers)
                r = c.getresponse()
                data = r.read()
                return r.status, (json.loads(data) if data else None)
            except (http.client.HTTPException, OSError):
                c.close()
                self.local.c = None
                if attempt:
                    raise
        raise AssertionError("unreachable")


class SandboxdServer(System):
    """`sandboxd serve` with warm caches, called over HTTP with keep-alive connections."""

    kind = "sandboxd"

    def __init__(self, ws: "Workspace", snapshots: bool):
        self.ws = ws
        self.snapshots = snapshots
        self.name = "sandboxd-http" if snapshots else "sandboxd-http-nosnap"
        self.port = free_port()
        variant = "snap" if snapshots else "nosnap"
        cfg = ws.config(variant, port=self.port, snapshots="on" if snapshots else "off")
        self.log_path = ws.root / f"server-{variant}.log"
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [str(ws.bin), "serve", "--config", str(cfg)],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            cwd=ws.root,
        )
        self.http = Http(self.port, ws.token)
        self.startup_s = self._wait_ready()

    def _wait_ready(self, timeout: float = 900) -> float:
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            if self.proc.poll() is not None:
                raise RunError(f"server exited {self.proc.returncode}: {self.tail()}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
                c.request("GET", "/healthz")
                if c.getresponse().status == 200:
                    c.close()
                    return round(time.monotonic() - t0, 2)
                c.close()
            except OSError:
                pass
            time.sleep(0.2)
        raise RunError(f"server not ready after {timeout}s: {self.tail()}")

    def tail(self) -> str:
        self.log.flush()
        return self.log_path.read_bytes()[-1500:].decode(errors="replace")

    def request(self, scn: Scenario) -> dict:
        body: dict = {"language": scn.language, "code": scn.code}
        if scn.uses_input:
            body["files"] = [{"name": "data.csv", "content": self.ws.csv_text}]
        return body

    def run(self, scn: Scenario) -> None:
        status, r = self.http.call("POST", "/v1/runs", self.request(scn))
        if status != 200 or not isinstance(r, dict) or r.get("outcome") != "ok":
            raise RunError(f"HTTP {status}: {json.dumps(r)[:300]}")
        check_output(scn.expect, r["stdout"])

    def rss(self) -> float | None:
        return rss_mib(self.proc.pid)

    # Sessions -------------------------------------------------------------------------------
    def open_session(self, language: str) -> str:
        status, r = self.http.call("POST", "/v1/sessions", {"language": language, "policy": "bench"})
        if status != 201 or not isinstance(r, dict):
            raise RunError(f"session create HTTP {status}: {json.dumps(r)[:300]}")
        return r["session_id"]

    def session_call(self, sid: str, code: str) -> str:
        status, r = self.http.call("POST", f"/v1/sessions/{sid}/runs", {"code": code})
        if status != 200 or not isinstance(r, dict) or r.get("outcome") != "ok":
            raise RunError(f"session call HTTP {status}: {json.dumps(r)[:300]}")
        return r["stdout"]

    def close_session(self, sid: str) -> None:
        self.http.call("DELETE", f"/v1/sessions/{sid}")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


INTERP = {"python": ("python", PY_IMAGE), "javascript": ("node", JS_IMAGE)}


class DockerRun(System):
    """`docker run --rm` per execution: a cold container."""

    kind = "container"

    def __init__(self, ws: "Workspace", runtime: str | None):
        self.ws = ws
        self.runtime = runtime
        self.name = "gvisor-run" if runtime == "runsc" else "docker-run"

    def base(self) -> list[str]:
        rt = ["--runtime", self.runtime] if self.runtime else []
        return [
            "docker", "run", "--rm", "--network", "none", *rt,
            "-v", f"{self.ws.progs}:/bench:ro", "-v", f"{self.ws.data}:/in:ro",
        ]

    def run(self, scn: Scenario) -> None:
        exe, image = INTERP[scn.language]
        p = subprocess.run(
            [*self.base(), image, exe, f"/bench/{scn.file}"], capture_output=True, text=True, timeout=120
        )
        if p.returncode != 0:
            raise RunError(f"exit {p.returncode}: {p.stderr[-300:]}")
        check_output(scn.expect, p.stdout)


class DockerExec(System):
    """`docker exec` into a running container: warm container, new interpreter process."""

    kind = "container"

    def __init__(self, ws: "Workspace", runtime: str | None):
        self.ws = ws
        self.name = "gvisor-exec" if runtime == "runsc" else "docker-exec"
        self.cids: dict[str, str] = {}
        launcher = DockerRun(ws, runtime)
        for lang, (_, image) in INTERP.items():
            self.cids[lang] = sh([*launcher.base()[:2], "-d", *launcher.base()[3:], image, "sleep", "infinity"]).strip()

    def run(self, scn: Scenario) -> None:
        exe, _ = INTERP[scn.language]
        p = subprocess.run(
            ["docker", "exec", self.cids[scn.language], exe, f"/bench/{scn.file}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if p.returncode != 0:
            raise RunError(f"exit {p.returncode}: {p.stderr[-300:]}")
        check_output(scn.expect, p.stdout)

    def close(self) -> None:
        if self.cids:
            subprocess.run(["docker", "rm", "-f", *self.cids.values()], capture_output=True)


# --------------------------------------------------------------------------------------------
# Workspace: programs, data, config, policy, token
# --------------------------------------------------------------------------------------------


class Workspace:
    def __init__(self, root: Path, sandboxd: Path, cache: Path, max_concurrent: int):
        self.root = root
        self.bin = sandboxd.resolve()
        self.cache = cache
        self.max_concurrent = max_concurrent
        self.progs = root / "progs"
        self.data = root / "data"
        self.policies = root / "policies"
        for d in (self.progs, self.data, self.policies, root / "work"):
            d.mkdir(parents=True, exist_ok=True)
        self.csv_text = make_csv()
        (self.data / "data.csv").write_text(self.csv_text, newline="")
        self.token = "sbx_" + secrets.token_hex(32)
        self.token_hash = hashlib.sha256(self.token.encode()).hexdigest()
        (self.policies / "bench.toml").write_text(
            'version = 1\nname = "bench"\ndescription = "Benchmarks: default limits, sessions on"\n'
            "[session]\nenabled = true\nmax_calls = 100000\nmax_sessions = 64\n"
        )
        self.scenarios = {
            "hello-py": Scenario("hello-py", "python", "hello.py", HELLO_PY, "1\n"),
            "hello-js": Scenario("hello-js", "javascript", "hello.js", HELLO_JS, "1\n"),
        }
        for s in self.scenarios.values():
            (self.progs / s.file).write_text(s.code)
        (self.progs / "csv_agg.py").write_text(CSV_PY)
        self.scenarios["csv-py"] = Scenario(
            "csv-py", "python", "csv_agg.py", CSV_PY, expected_csv_output(self.data / "data.csv"), True
        )

    def config(self, variant: str, port: int = 0, snapshots: str = "auto") -> Path:
        p = self.root / f"sandboxd-{variant}.toml"
        q = lambda x: json.dumps(str(x))  # noqa: E731  TOML basic strings accept JSON escapes
        p.write_text(
            f"policy_dir = {q(self.policies)}\ncache_dir = {q(self.cache)}\nwork_dir = {q(self.root / 'work')}\n"
            f'[server]\nlisten = "127.0.0.1:{port or 8080}"\nmax_concurrent = {self.max_concurrent}\n'
            "queue_depth = 1024\nqueue_timeout = \"120s\"\n"
            f'[auth]\ntokens = [ {{ name = "bench", sha256 = "{self.token_hash}" }} ]\n'
            f'[audit]\nsink = "file"\npath = {q(self.root / f"audit-{variant}.jsonl")}\n'
            f'[runtime]\nsnapshots = "{snapshots}"\nmax_sessions = 64\n'
        )
        return p


# --------------------------------------------------------------------------------------------
# Measurements
# --------------------------------------------------------------------------------------------


class Bench:
    def __init__(self, args: argparse.Namespace, ws: Workspace):
        self.args = args
        self.ws = ws
        self.results: list[dict] = []
        self.skipped: list[dict] = []

    def skip(self, system: str, reason: str) -> None:
        log(f"skip {system}: {reason}")
        self.skipped.append({"system": system, "reason": reason})

    def add(self, entry: dict) -> None:
        log(json.dumps(entry))
        self.results.append(entry)

    def latency(self, sysm: System, scn: Scenario) -> None:
        errors, first_error, samples = 0, None, []
        for i in range(self.args.warmup + self.args.iterations):
            t = time.perf_counter_ns()
            try:
                sysm.run(scn)
            except Exception as e:  # noqa: BLE001 — record and continue
                errors += 1
                first_error = first_error or str(e)
                continue
            if i >= self.args.warmup:
                samples.append(time.perf_counter_ns() - t)
        entry = {"system": sysm.name, "scenario": scn.name, "metric": "latency", "errors": errors}
        if samples:
            entry |= latency_stats(samples)
        if first_error:
            entry["first_error"] = first_error[:500]
        self.add(entry)

    def throughput(self, sysm: System, scn: Scenario) -> None:
        for c in self.args.concurrency:
            runs = max(self.args.throughput_runs, c * 4)
            errors = 0

            def one(_: int) -> bool:
                try:
                    sysm.run(scn)
                    return True
                except Exception:  # noqa: BLE001
                    return False

            with cf.ThreadPoolExecutor(max_workers=c) as ex:
                list(ex.map(one, range(c)))  # warm each worker's connection
                t = time.perf_counter()
                ok = list(ex.map(one, range(runs)))
                secs = time.perf_counter() - t
            errors = ok.count(False)
            self.add(
                {
                    "system": sysm.name,
                    "scenario": scn.name,
                    "metric": "throughput",
                    "concurrency": c,
                    "runs": runs,
                    "errors": errors,
                    "seconds": round(secs, 3),
                    "runs_per_s": round((runs - errors) / secs, 2),
                }
            )

    def session_latency(self, srv: SandboxdServer, language: str) -> None:
        init, cell = ("n = 0", "n += 1\nprint(n)") if language == "python" else ("var n = 0", "n += 1; console.log(n)")
        sid = srv.open_session(language)
        try:
            srv.session_call(sid, init)
            samples, errors, first_error = [], 0, None
            for i in range(1, self.args.warmup + self.args.iterations + 1):
                t = time.perf_counter_ns()
                try:
                    check_output(f"{i}\n", srv.session_call(sid, cell))
                except Exception as e:  # noqa: BLE001
                    errors += 1
                    first_error = first_error or str(e)
                    break  # the state is gone or out of step; later calls would only repeat this
                if i > self.args.warmup:
                    samples.append(time.perf_counter_ns() - t)
        finally:
            srv.close_session(sid)
        entry = {
            "system": srv.name,
            "scenario": f"session-{'py' if language == 'python' else 'js'}",
            "metric": "latency",
            "errors": errors,
        }
        if samples:
            entry |= latency_stats(samples)
        if first_error:
            entry["first_error"] = first_error[:500]
        self.add(entry)

    def sandboxd_memory(self, srv: SandboxdServer) -> None:
        k = self.args.memory_sandboxes
        if srv.rss() is None:
            self.skip(f"{srv.name} memory", "no /proc RSS on this OS")
            return
        time.sleep(1)
        base = srv.rss()
        sids = [srv.open_session("python") for _ in range(k)]
        try:
            for sid in sids:
                srv.session_call(sid, "x = 1")
            time.sleep(1)
            idle = srv.rss()
        finally:
            for sid in sids:
                srv.close_session(sid)
        self.add(
            {
                "system": srv.name,
                "scenario": "idle-session-py",
                "metric": "memory",
                "count": k,
                "per_sandbox_mib": round((idle - base) / k, 2),
                "baseline_mib": round(base, 1),
                "method": "server RSS delta with N idle Python sessions",
            }
        )
        # Concurrent runs: each sleeps, the peak RSS is sampled while they are all live.
        time.sleep(1)
        base = srv.rss()
        scn = Scenario("sleep-py", "python", "sleep.py", SLEEP_PY.format(secs=3), "1\n")
        peak = base
        with cf.ThreadPoolExecutor(max_workers=k) as ex:
            futs = [ex.submit(srv.run, scn) for _ in range(k)]
            while not all(f.done() for f in futs):
                peak = max(peak, srv.rss() or 0)
                time.sleep(0.05)
            errors = sum(1 for f in futs if f.exception())
        self.add(
            {
                "system": srv.name,
                "scenario": "live-run-py",
                "metric": "memory",
                "count": k,
                "errors": errors,
                "per_sandbox_mib": round((peak - base) / k, 2),
                "baseline_mib": round(base, 1),
                "method": "peak server RSS delta with N concurrent sleeping Python runs",
            }
        )

    def docker_memory(self, name: str, runtime: str | None) -> None:
        k = self.args.memory_sandboxes
        launcher = DockerRun(self.ws, runtime)
        base = launcher.base()
        cmd = [*base[:2], "-d", *base[3:], PY_IMAGE, "python", "-c", "import time; time.sleep(600)"]
        cids = []
        try:
            for _ in range(k):
                cids.append(sh(cmd).strip())
            time.sleep(3)
            out = sh(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", *cids])
            used = [parse_mem(line.split("/")[0]) for line in out.splitlines() if line.strip()]
            self.add(
                {
                    "system": name,
                    "scenario": "idle-session-py",
                    "metric": "memory",
                    "count": k,
                    "per_sandbox_mib": round(sum(used) / len(used), 2),
                    "method": "docker stats (container cgroup memory) of N idle Python containers",
                }
            )
        finally:
            if cids:
                subprocess.run(["docker", "rm", "-f", *cids], capture_output=True)


def parse_mem(s: str) -> float:
    s = s.strip()
    units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "kB": 1 / 1024 / 1.024, "MB": 1 / 1.048576, "GB": 1000 / 1.048576, "B": 1 / (1 << 20)}
    for u in sorted(units, key=len, reverse=True):
        if s.endswith(u):
            return float(s[: -len(u)]) * units[u]
    raise ValueError(f"unknown memory unit in {s!r}")


# --------------------------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------------------------


def try_out(cmd: list[str]) -> str | None:
    try:
        return sh(cmd, timeout=60).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def host_info(sandboxd: Path, docker: bool, runsc: bool) -> dict:
    cpu = None
    mem = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem = round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        cpu = platform.processor() or None
    info = {
        "os": platform.platform(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu": cpu,
        "vcpus": os.cpu_count(),
        "memory_gib": mem,
        "harness_python": platform.python_version(),
        "sandboxd_version": try_out([str(sandboxd), "version"]),
    }
    if docker:
        info["docker"] = try_out(["docker", "version", "--format", "{{.Server.Version}}"])
        info["images"] = {
            img: try_out(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", img])
            for img in (PY_IMAGE, JS_IMAGE)
        }
        info["image_versions"] = {
            PY_IMAGE: try_out(["docker", "run", "--rm", PY_IMAGE, "python", "-c", "import sys; print(sys.version.split()[0])"]),
            JS_IMAGE: try_out(["docker", "run", "--rm", JS_IMAGE, "node", "--version"]),
        }
    if runsc:
        v = try_out(["runsc", "--version"])
        info["runsc"] = v.splitlines()[0] if v else None
    return info


def docker_ok() -> str | None:
    if not shutil.which("docker"):
        return "docker CLI not found"
    if try_out(["docker", "info", "--format", "{{.ServerVersion}}"]) is None:
        return "docker daemon not reachable"
    for img in (PY_IMAGE, JS_IMAGE):
        if try_out(["docker", "image", "inspect", img]) is None:
            return f"image {img} not pulled"
    return None


def runsc_ok() -> str | None:
    rts = try_out(["docker", "info", "--format", "{{json .Runtimes}}"]) or ""
    if "runsc" not in rts:
        return "runsc runtime not registered with docker"
    if try_out(["docker", "run", "--rm", "--runtime", "runsc", PY_IMAGE, "python", "-c", "print(1)"]) != "1":
        return "runsc runtime does not start containers on this runner"
    return None


# --------------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandboxd", type=Path, required=True, help="release binary to benchmark")
    ap.add_argument("--out", type=Path, default=Path("bench-results.json"))
    ap.add_argument("--workdir", type=Path, help="scratch directory (default: a new temp dir)")
    ap.add_argument("--cache-dir", type=Path, help="sandboxd cache (default: <workdir>/cache)")
    ap.add_argument("--iterations", type=int, default=200, help="latency samples per scenario")
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--throughput-runs", type=int, default=200, help="runs per concurrency level")
    ap.add_argument("--concurrency", type=lambda s: [int(x) for x in s.split(",")], default=[1, 4, 16])
    ap.add_argument("--memory-sandboxes", type=int, default=8)
    ap.add_argument("--max-concurrent", type=int, default=16, help="sandboxd [server] max_concurrent")
    ap.add_argument("--docker", choices=["auto", "off"], default="auto")
    ap.add_argument("--gvisor", choices=["auto", "off"], default="auto")
    ap.add_argument("--cli-iterations", type=int, help="latency samples for the cold CLI (default: --iterations)")
    args = ap.parse_args()
    if args.iterations < 1 or args.throughput_runs < 1 or args.memory_sandboxes < 1:
        ap.error("counts must be positive")

    root = args.workdir or Path(tempfile.mkdtemp(prefix="sandboxd-bench-"))
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = (args.cache_dir or root / "cache").resolve()
    ws = Workspace(root, args.sandboxd, cache, args.max_concurrent)
    bench = Bench(args, ws)

    docker_reason = "disabled (--docker off)" if args.docker == "off" else docker_ok()
    runsc_reason = None
    if docker_reason:
        runsc_reason = "needs docker"
    elif args.gvisor == "off":
        runsc_reason = "disabled (--gvisor off)"
    else:
        runsc_reason = runsc_ok()

    started = dt.datetime.now(dt.timezone.utc)
    results = {
        "schema": SCHEMA,
        "started_at": started.isoformat(timespec="seconds"),
        "ci": {
            k: os.environ.get(v)
            for k, v in {
                "sha": "GITHUB_SHA",
                "run_id": "GITHUB_RUN_ID",
                "server_url": "GITHUB_SERVER_URL",
                "repository": "GITHUB_REPOSITORY",
                "runner": "RUNNER_NAME",
            }.items()
        },
        "host": host_info(ws.bin, docker_reason is None, runsc_reason is None),
        "config": {
            "iterations": args.iterations,
            "warmup": args.warmup,
            "throughput_runs": args.throughput_runs,
            "concurrency": args.concurrency,
            "memory_sandboxes": args.memory_sandboxes,
            "max_concurrent": args.max_concurrent,
            "csv_bytes": len(ws.csv_text),
        },
        "startup": {},
        "results": bench.results,
        "skipped": bench.skipped,
    }
    if results["ci"]["sha"] is None:
        results["ci"]["sha"] = try_out(["git", "rev-parse", "HEAD"])

    def save() -> None:
        results["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        args.out.write_text(json.dumps(results, indent=2) + "\n")

    hello_py, hello_js, csv_py = (ws.scenarios[k] for k in ("hello-py", "hello-js", "csv-py"))
    scenarios = [hello_py, hello_js, csv_py]
    try:
        # 1. sandboxd server (snapshots on): builds the caches the other sandboxd systems reuse.
        for snap in (True, False):
            name = "sandboxd-http" if snap else "sandboxd-http-nosnap"
            log(f"starting {name}")
            try:
                srv = SandboxdServer(ws, snap)
            except Exception as e:  # noqa: BLE001
                bench.skip(name, f"server did not start: {e}")
                continue
            results["startup"][name] = srv.startup_s
            try:
                for scn in scenarios:
                    bench.latency(srv, scn)
                if snap:
                    for lang in ("python", "javascript"):
                        try:
                            bench.session_latency(srv, lang)
                        except Exception as e:  # noqa: BLE001
                            bench.skip(f"{name} session-{lang}", str(e))
                bench.throughput(srv, hello_py)
                if snap:
                    try:
                        bench.sandboxd_memory(srv)
                    except Exception as e:  # noqa: BLE001
                        bench.skip(f"{name} memory", str(e))
            finally:
                srv.close()
            save()

        # 2. sandboxd CLI: a process per run (cache already warm).
        cli = SandboxdCli(ws)
        saved = args.iterations
        args.iterations = args.cli_iterations or args.iterations
        for scn in scenarios:
            bench.latency(cli, scn)
        args.iterations = saved
        save()

        # 3. Containers.
        runtimes = [("docker", None, docker_reason), ("gvisor", "runsc", runsc_reason)]
        for label, rt, reason in runtimes:
            if reason:
                bench.skip(f"{label}-run / {label}-exec", reason)
                continue
            run = DockerRun(ws, rt)
            for scn in scenarios:
                bench.latency(run, scn)
            bench.throughput(run, hello_py)
            save()
            try:
                ex = DockerExec(ws, rt)
            except Exception as e:  # noqa: BLE001
                bench.skip(f"{label}-exec", f"container did not start: {e}")
            else:
                try:
                    for scn in scenarios:
                        bench.latency(ex, scn)
                    bench.throughput(ex, hello_py)
                finally:
                    ex.close()
            try:
                bench.docker_memory(run.name, rt)
            except Exception as e:  # noqa: BLE001
                bench.skip(f"{run.name} memory", str(e))
            save()
    finally:
        save()
        log(f"results written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
