"""Self-tests for the benchmark harness (no sandboxd, no Docker needed).

    python -I -m unittest discover -s scripts/bench -p "test_*.py"
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(f"bench_{name}", HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


run = load("run")
render = load("render")


def sample_results():
    lat = lambda sysname, scn, p50: {  # noqa: E731
        "system": sysname, "scenario": scn, "metric": "latency", "errors": 0, "n": 200,
        "p50_ms": p50, "p95_ms": p50 * 1.5, "p99_ms": p50 * 2, "mean_ms": p50, "min_ms": p50, "max_ms": p50 * 3,
    }
    return {
        "schema": 1,
        "started_at": "2026-11-20T12:00:00+00:00",
        "ci": {"sha": "0123456789abcdef", "run_id": "42", "server_url": "https://github.com", "repository": "o/r"},
        "host": {"os": "Linux", "cpu": "Test CPU", "vcpus": 4, "memory_gib": 15.6, "docker": "28.0",
                 "images": {"python:3.15-slim": "python@sha256:aa"}, "image_versions": {"python:3.15-slim": "3.15.0"}},
        "config": {"iterations": 200},
        "startup": {"sandboxd-http": 1.5},
        "results": [
            lat("sandboxd-http", "hello-py", 9.5),
            lat("sandboxd-http", "hello-js", 3.4),
            lat("sandboxd-http", "session-py", 1.2),
            lat("sandboxd-http-nosnap", "hello-py", 60.0),
            lat("docker-run", "hello-py", 450.0),
            {"system": "sandboxd-http", "scenario": "hello-py", "metric": "throughput", "concurrency": 1, "runs_per_s": 90.0, "errors": 0},
            {"system": "sandboxd-http", "scenario": "hello-py", "metric": "throughput", "concurrency": 4, "runs_per_s": 310.0, "errors": 0},
            {"system": "docker-run", "scenario": "hello-py", "metric": "throughput", "concurrency": 4, "runs_per_s": 6.0, "errors": 2},
            {"system": "sandboxd-http", "scenario": "idle-session-py", "metric": "memory", "count": 8, "per_sandbox_mib": 22.5, "method": "rss"},
            {"system": "docker-exec", "scenario": "csv-py", "metric": "latency", "errors": 3, "first_error": "boom"},
        ],
        "skipped": [{"system": "gvisor-run / gvisor-exec", "reason": "runsc runtime not registered with docker"}],
    }


class Stats(unittest.TestCase):
    def test_nearest_rank_percentiles(self):
        xs = list(range(1, 101))
        self.assertEqual(run.percentile(xs, 50), 50)
        self.assertEqual(run.percentile(xs, 95), 95)
        self.assertEqual(run.percentile(xs, 99), 99)
        self.assertEqual(run.percentile([7], 99), 7)
        s = run.latency_stats([1_000_000, 3_000_000, 2_000_000])
        self.assertEqual((s["n"], s["p50_ms"], s["max_ms"], s["mean_ms"]), (3, 2.0, 3.0, 2.0))

    def test_csv_is_deterministic_and_about_1_mib(self):
        a, b = run.make_csv(), run.make_csv()
        self.assertEqual(a, b)
        self.assertTrue((1 << 20) <= len(a) < (1 << 20) + 200)
        self.assertTrue(a.startswith("id,category,amount,ts\n"))

    def test_docker_memory_units(self):
        self.assertAlmostEqual(run.parse_mem("12.5MiB"), 12.5)
        self.assertAlmostEqual(run.parse_mem("1GiB"), 1024)
        self.assertAlmostEqual(run.parse_mem("512KiB"), 0.5)
        with self.assertRaises(ValueError):
            run.parse_mem("12 parsecs")


class Render(unittest.TestCase):
    def test_nfr_verdicts(self):
        rows = {r[0]: r for r in render.nfr_rows(sample_results())}
        self.assertIn("met", rows["Python `print(1)` through the service (snapshot + pool)"][3])
        self.assertIn("missed", rows["JavaScript `console.log(1)` through the service"][3])
        self.assertIn("met", rows["Python runs per second"][3])  # best level: 310 runs/s
        self.assertEqual(rows["Idle session memory"][2], "22.50 MiB")
        self.assertEqual(render.nfr_rows({"results": []})[0][3], "not measured")

    def test_page_has_every_section_and_no_hand_numbers(self):
        md = render.render(sample_results())
        for want in [
            "## NFR-P1 targets",
            "### Python `print(1)`",
            "## Throughput",
            "## Memory per sandbox",
            "## Server start-up",
            "runsc runtime not registered",
            "first: `boom`",
            "[bench run 42](https://github.com/o/r/actions/runs/42)",
            "6.3× the snapshot path",
            "6.0 (2 errors)",
            "`python:3.15-slim` | 3.15.0 · `python@sha256:aa`",
            "## Methodology",
        ]:
            self.assertIn(want, md)
        # sandboxd rows come before the containers in every table.
        self.assertLess(md.index("sandboxd server, snapshots"), md.index("`docker run --rm`"))

    def test_placeholder_without_results(self):
        md = render.render(None)
        self.assertIn("_No published run yet._", md)
        self.assertIn("## Methodology", md)
        self.assertNotIn("NFR-P1 targets", md)

    def test_render_cli_round_trip(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.json"
            p.write_text(json.dumps(sample_results()))
            out = subprocess.run(
                [sys.executable, "-I", str(HERE / "render.py"), str(p)], capture_output=True, check=True
            ).stdout.decode("utf-8")
        self.assertTrue(out.startswith("# Benchmarks\n"))


if __name__ == "__main__":
    unittest.main()
