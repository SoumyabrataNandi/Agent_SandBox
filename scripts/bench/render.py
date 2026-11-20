#!/usr/bin/env python3
"""Render a bench results file (from run.py) as docs/BENCHMARKS.md (C3-U5, FR-B1.3).

    python -I scripts/bench/render.py bench-results.json > docs/BENCHMARKS.md
    python -I scripts/bench/render.py --none > docs/BENCHMARKS.md   # methodology only

The published numbers come only from this script and a `bench.yml` results file, never by hand.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SYSTEM_LABELS = {
    "sandboxd-http": "sandboxd server, snapshots (HTTP, warm)",
    "sandboxd-http-nosnap": "sandboxd server, no snapshots (HTTP, warm)",
    "sandboxd-cli": "sandboxd CLI (process per run)",
    "docker-run": "`docker run --rm` (cold container)",
    "docker-exec": "`docker exec` (warm container)",
    "gvisor-run": "gVisor `docker run --runtime runsc --rm`",
    "gvisor-exec": "gVisor `docker exec` (warm container)",
}
SYSTEM_ORDER = list(SYSTEM_LABELS)
SCENARIO_LABELS = {
    "hello-py": "Python `print(1)`",
    "hello-js": "JavaScript `console.log(1)` (sandboxd: QuickJS; containers: Node.js)",
    "csv-py": "Python: parse and aggregate a 1 MiB CSV, print JSON",
    "session-py": "Python session call (`n += 1; print(n)`)",
    "session-js": "JavaScript session call (`n += 1; console.log(n)`)",
}

# NFR-P1 (requirements.md): (label, how it is measured, limit, comparison, getter).
NFR = [
    ("Python `print(1)` through the service (snapshot + pool)", "p50 latency, sandboxd-http hello-py", 15.0, "ms",
     lambda r: get(r, "sandboxd-http", "hello-py", "latency", "p50_ms"), "le"),
    ("JavaScript `console.log(1)` through the service", "p50 latency, sandboxd-http hello-js", 3.0, "ms",
     lambda r: get(r, "sandboxd-http", "hello-js", "latency", "p50_ms"), "le"),
    ("Session call overhead", "p50 latency of a trivial session cell, end to end over HTTP", 2.0, "ms",
     lambda r: get(r, "sandboxd-http", "session-py", "latency", "p50_ms"), "le"),
    ("Python runs per second", "best of the measured concurrency levels, sandboxd-http hello-py", 100.0, "runs/s",
     lambda r: best_throughput(r, "sandboxd-http", "hello-py"), "ge"),
    ("Idle session memory", "server RSS delta per idle Python session", 40.0, "MiB",
     lambda r: get(r, "sandboxd-http", "idle-session-py", "memory", "per_sandbox_mib"), "le"),
]

METHODOLOGY = """\
## Methodology
- **Harness:** [`scripts/bench/run.py`](../scripts/bench/run.py) (Python standard library, Docker CLI,
  the sandboxd release binary). It runs in the manually started [`bench.yml`](../.github/workflows/bench.yml)
  workflow on a GitHub-hosted `ubuntu-latest` runner. The results JSON goes to the job summary, a build
  artifact and the `ci-results` branch (`bench/<sha>.json`). This page is generated from that file by
  [`scripts/bench/render.py`](../scripts/bench/render.py).
- **Latency:** each system is warmed up first. Then each scenario is run *N* times in sequence, timed
  with `time.perf_counter_ns` around the whole client call: an HTTP request on a keep-alive connection,
  a `sandboxd run` process, or a `docker run`/`docker exec` process. Every run's output is checked
  against the expected output, and a wrong result counts as an error, not as a sample.
  Percentiles are nearest-rank.
- **Throughput:** `hello-py` with 1/4/16 client threads. Each level runs a fixed number of executions;
  the rate is successful runs ÷ wall time.
- **Memory:**
  - sandboxd: the server's RSS (`/proc/<pid>/status`) before and after opening *N* idle Python sessions,
    divided by *N*. Also the peak RSS while *N* Python runs sleep concurrently.
  - Containers: `docker stats` memory (the container's cgroup) of *N* idle `python` containers.
- **Systems:**
  - The sandboxd server runs with its defaults (pooling on), `max_concurrent` 16, file audit sink and
    warm caches. It is measured with snapshots on and with snapshots off.
  - The CLI is cold: one process per run, with a warm on-disk cache.
  - Containers use `--network none` and read-only bind mounts for the program and the data.
- **Workloads:** `print(1)`, `console.log(1)`, and a ~1 MiB CSV that is parsed with `csv.DictReader` and
  aggregated per category to a JSON line. The CSV is generated from a fixed seed. The sandboxd server
  receives it in the request body; the CLI and the containers read it from a mounted file.

## Caveats
- **Different guarantees.** A sandboxd run is a fresh WebAssembly instance: no shared memory between runs,
  WASI-only access, fuel and wall-clock limits. A container is a Linux process tree with a kernel
  attack surface; gVisor adds a user-space kernel. `docker exec` reuses the container's filesystem
  and namespaces.
- **Different interpreters for JavaScript:** sandboxd runs QuickJS-ng; the containers run Node.js (V8).
  Node starts more slowly, but it executes heavy code much faster than an interpreter.
- **Python in wasm is slower at compute-heavy work** than native CPython: the CSV row shows the
  trade-off.
- **Shared, virtualised runners:** numbers vary from run to run. Compare the systems within one run, not
  across runs.
- **Memory measures different things:** process RSS deltas (sandboxd) are not cgroup accounting
  (containers, which includes page cache). Container numbers exclude the Docker daemon and shim processes.
"""


def get(results: dict, system: str, scenario: str, metric: str, key: str):
    for e in results.get("results", []):
        if (e.get("system"), e.get("scenario"), e.get("metric")) == (system, scenario, metric):
            return e.get(key)
    return None


def best_throughput(results: dict, system: str, scenario: str):
    vals = [
        e["runs_per_s"]
        for e in results.get("results", [])
        if (e.get("system"), e.get("scenario"), e.get("metric")) == (system, scenario, "throughput")
        and e.get("runs_per_s") is not None
    ]
    return max(vals) if vals else None


def fmt(v, nd: int = 1) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.{nd}f}"
    return f"{v:,}"


def nfr_rows(results: dict) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for label, how, limit, unit, getter, cmp in NFR:
        v = getter(results)
        if v is None:
            verdict = "not measured"
        else:
            ok = v <= limit if cmp == "le" else v >= limit
            verdict = "✅ met" if ok else "❌ missed"
        sign = "≤" if cmp == "le" else "≥"
        rows.append((label, f"{sign} {limit:g} {unit}", f"{fmt(v, 2)} {unit}" if v is not None else "—", verdict, how))
    return rows


def table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def systems_in(entries: list[dict]) -> list[str]:
    seen = {e["system"] for e in entries}
    return [s for s in SYSTEM_ORDER if s in seen] + sorted(seen - set(SYSTEM_ORDER))


def label(system: str) -> str:
    return SYSTEM_LABELS.get(system, system)


def render(results: dict | None) -> str:
    out = ["# Benchmarks", ""]
    out.append(
        "<!-- Generated by scripts/bench/render.py from a bench.yml results file. Do not edit by hand. -->"
    )
    out.append("")
    if results is None:
        out += [
            "_No published run yet._ Start the **bench** workflow (Actions → bench → Run workflow). Then",
            "generate this page from its results file:",
            "",
            "```bash",
            "git fetch origin ci-results",
            "git show origin/ci-results:bench/latest.json > bench-results.json",
            "python -I scripts/bench/render.py bench-results.json > docs/BENCHMARKS.md",
            "```",
            "",
            METHODOLOGY,
        ]
        return "\n".join(out)

    ci = results.get("ci", {})
    host = results.get("host", {})
    cfg = results.get("config", {})
    entries = results.get("results", [])
    run_url = None
    if ci.get("server_url") and ci.get("repository") and ci.get("run_id"):
        run_url = f"{ci['server_url']}/{ci['repository']}/actions/runs/{ci['run_id']}"
    src = f"[bench run {ci['run_id']}]({run_url})" if run_url else "a local run"
    sha = (ci.get("sha") or "unknown")[:12]
    out.append(
        f"Measured {results.get('started_at', '?')} by {src} at commit `{sha}`, on {host.get('vcpus', '?')} vCPU "
        f"({host.get('cpu') or host.get('arch', '?')}), {fmt(host.get('memory_gib'))} GiB RAM, "
        f"{cfg.get('iterations', '?')} samples per latency row."
    )
    out.append("")

    out += ["## NFR-P1 targets", ""]
    out.append(table(["Target", "Limit", "Measured", "Result", "How"], [list(r) for r in nfr_rows(results)]))
    no_snap = get(results, "sandboxd-http-nosnap", "hello-py", "latency", "p50_ms")
    snap = get(results, "sandboxd-http", "hello-py", "latency", "p50_ms")
    if no_snap is not None and snap is not None:
        out += [
            "",
            f"Without snapshots, the same Python run takes {fmt(no_snap, 2)} ms (p50), "
            f"{no_snap / snap:.1f}× the snapshot path. The CI performance smoke test guards that path "
            "against regressions (NFR-P1 \"no regression on the non-snapshot path\").",
        ]
    out.append("")

    lat = [e for e in entries if e.get("metric") == "latency"]
    if lat:
        out += ["## Latency (ms, end to end, client side)", ""]
        for scn in [s for s in SCENARIO_LABELS if any(e["scenario"] == s for e in lat)]:
            rows = []
            for sysname in systems_in([e for e in lat if e["scenario"] == scn]):
                e = next(x for x in lat if x["system"] == sysname and x["scenario"] == scn)
                rows.append(
                    [
                        label(sysname),
                        fmt(e.get("p50_ms"), 2),
                        fmt(e.get("p95_ms"), 2),
                        fmt(e.get("p99_ms"), 2),
                        fmt(e.get("n")),
                        fmt(e.get("errors")),
                    ]
                )
            out += [f"### {SCENARIO_LABELS[scn]}", "", table(["System", "p50", "p95", "p99", "n", "errors"], rows), ""]

    thr = [e for e in entries if e.get("metric") == "throughput"]
    if thr:
        levels = sorted({e["concurrency"] for e in thr})
        out += ["## Throughput: Python `print(1)` (runs/s)", ""]
        rows = []
        for sysname in systems_in(thr):
            row = [label(sysname)]
            for c in levels:
                e = next((x for x in thr if x["system"] == sysname and x["concurrency"] == c), None)
                cell = fmt(e.get("runs_per_s")) if e else "—"
                if e and e.get("errors"):
                    cell += f" ({e['errors']} errors)"
                row.append(cell)
            rows.append(row)
        out += [table(["System"] + [f"concurrency {c}" for c in levels], rows), ""]

    mem = [e for e in entries if e.get("metric") == "memory"]
    if mem:
        out += ["## Memory per sandbox (MiB)", ""]
        rows = [
            [label(e["system"]), e["scenario"], fmt(e.get("per_sandbox_mib")), fmt(e.get("count")), e.get("method", "")]
            for e in mem
        ]
        out += [table(["System", "Scenario", "MiB each", "N", "Method"], rows), ""]

    start = results.get("startup", {})
    if start:
        out += [
            "## Server start-up",
            "",
            "Time from process start until `/healthz` answers. The first start builds the compile cache"
            " (and the snapshots); this is part of the same run, not a benchmark row.",
            "",
            table(["System", "Seconds"], [[label(k), fmt(v, 2)] for k, v in start.items()]),
            "",
        ]

    errs = [e for e in entries if e.get("first_error")]
    skipped = results.get("skipped", [])
    if skipped or errs:
        out += ["## Not measured or with errors", ""]
        for s in skipped:
            out.append(f"- **{s['system']}**: skipped ({s['reason']})")
        for e in errs:
            out.append(f"- **{e['system']} / {e['scenario']}**: {e['errors']} errors; first: `{e['first_error'][:200]}`")
        out.append("")

    out += ["## Environment", ""]
    env_rows = [
        ["OS", host.get("os")],
        ["CPU", f"{host.get('cpu')} × {host.get('vcpus')} vCPU"],
        ["Memory", f"{fmt(host.get('memory_gib'))} GiB"],
        ["Docker", host.get("docker")],
        ["gVisor", host.get("runsc")],
    ]
    for img, digest in (host.get("images") or {}).items():
        ver = (host.get("image_versions") or {}).get(img)
        env_rows.append([f"`{img}`", f"{ver or '?'} · `{digest or '?'}`"])
    env_rows.append(["Settings", ", ".join(f"{k} {v}" for k, v in cfg.items())])
    out.append(table(["", ""], [[k, str(v) if v is not None else "—"] for k, v in env_rows]))
    if host.get("sandboxd_version"):
        out += ["", "```", host["sandboxd_version"], "```"]
    out += ["", METHODOLOGY]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="?", type=Path, help="results JSON from run.py")
    ap.add_argument("--none", action="store_true", help="render the page without results")
    args = ap.parse_args()
    if args.none == (args.results is not None):
        ap.error("give a results file or --none")
    results = None if args.none else json.loads(args.results.read_text(encoding="utf-8"))
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stdout.write(render(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
