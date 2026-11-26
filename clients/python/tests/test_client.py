"""Tests for sandboxd_client (cycle 6, FR-CL1.7).

Unit tests use a stub HTTP server. Integration tests need a real server: run them through
`clients/testserver.py`, which sets SANDBOXD_URL / SANDBOXD_TOKEN. Without those they are
skipped, unless SANDBOXD_REQUIRE_SERVER=1 (CI), which makes a missing server a failure.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sandboxd_client import RunResult, Sandboxd, SandboxdError  # noqa: E402


class Stub:
    """A tiny HTTP server answering from a list of (status, headers, body) per request."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_one(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                stub.requests.append((self.command, self.path, dict(self.headers), body))
                status, headers, payload = stub.replies.pop(0)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = handle_one

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


RESULT = {
    "run_id": "r1", "language": "python", "policy": "default", "outcome": "ok", "exit_code": 0,
    "stdout": "42\n", "stderr": "", "stdout_truncated": False, "stderr_truncated": False,
    "artifacts": [{"name": "a.txt", "size": 2, "sha256": "x", "content_base64": base64.b64encode(b"hi").decode()}],
    "limits_hit": [], "error": None, "fuel_used": 10, "peak_memory": 20,
    "timings": {"queued_ms": 0, "setup_ms": 1, "run_ms": 2, "collect_ms": 0, "total_ms": 3},
}


class UnitTests(unittest.TestCase):
    def test_headers_body_and_result(self):
        s = Stub([(200, {"Content-Type": "application/json"}, RESULT)])
        try:
            r = Sandboxd(s.url, "tok").run("print(6*7)", files={"t.txt": "x", "b.bin": b"\x00\xff"},
                                          limits={"wall_clock": "2s"})
            method, path, headers, body = s.requests[0]
            self.assertEqual((method, path), ("POST", "/v1/runs"))
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(headers["Authorization"], "Bearer tok")
            sent = json.loads(body)
            self.assertEqual(sent["files"][0], {"name": "t.txt", "content": "x"})
            self.assertEqual(sent["files"][1]["encoding"], "base64")
            self.assertEqual(base64.b64decode(sent["files"][1]["content"]), b"\x00\xff")
            self.assertNotIn("stdin", sent)
            self.assertTrue(r.ok)
            self.assertEqual(r.stdout, "42\n")
            self.assertEqual(r.artifact("a.txt").content, b"hi")
            self.assertEqual(r.timings.total_ms, 3)
        finally:
            s.close()

    def test_no_token_no_auth_header(self):
        s = Stub([(200, {}, {"status": "ok"})])
        try:
            c = Sandboxd(s.url, "")
            self.assertEqual(c.health(), {"status": "ok"})
            self.assertNotIn("Authorization", s.requests[0][2])
        finally:
            s.close()

    def test_error_mapping(self):
        s = Stub([(404, {}, {"error": {"code": "POLICY_NOT_FOUND", "message": "no policy 'x'"}}),
                  (502, {}, b"bad gateway")])
        try:
            c = Sandboxd(s.url, "t")
            with self.assertRaises(SandboxdError) as e:
                c.run("1", policy="x")
            self.assertEqual((e.exception.code, e.exception.status), ("POLICY_NOT_FOUND", 404))
            with self.assertRaises(SandboxdError) as e:
                c.run("1")
            self.assertEqual((e.exception.code, e.exception.status), ("HTTP_502", 502))
        finally:
            s.close()

    def test_retry_on_429(self):
        busy = (429, {"Retry-After": "0"}, {"error": {"code": "OVERLOADED", "message": "busy"}})
        s = Stub([busy, busy, (200, {}, RESULT)])
        try:
            self.assertTrue(Sandboxd(s.url, "t").run("1").ok)
            self.assertEqual(len(s.requests), 3)
        finally:
            s.close()
        s = Stub([busy, busy])
        try:
            with self.assertRaises(SandboxdError) as e:
                Sandboxd(s.url, "t", retries=1).run("1")
            self.assertEqual(e.exception.code, "OVERLOADED")
        finally:
            s.close()

    def test_unreachable(self):
        with self.assertRaises(SandboxdError) as e:
            Sandboxd("http://127.0.0.1:9", "t", timeout=2).health()
        self.assertEqual(e.exception.code, "UNREACHABLE")

    def test_stream_parsing(self):
        sse = (": keep-alive\n\n"
               "event: stdout\ndata: {\"text\":\"a\\n\"}\n\n"
               "event: stderr\ndata: {\"text\":\"?\",\"base64\":\"/w==\"}\n\n"
               "event: future\ndata: {}\n\n"
               "event: limit\ndata: {\"kind\":\"wall_clock\"}\n\n"
               f"event: result\ndata: {json.dumps(RESULT)}\n\n").encode()
        s = Stub([(200, {"Content-Type": "text/event-stream"}, sse)])
        try:
            evs = list(Sandboxd(s.url, "t").stream("print('a')"))
            self.assertEqual(s.requests[0][1], "/v1/runs?stream=true")
            self.assertEqual([e.type for e in evs], ["stdout", "stderr", "limit", "result"])
            self.assertEqual(evs[0].text, "a\n")
            self.assertEqual(evs[1].data, b"\xff")
            self.assertEqual(evs[2].limit, "wall_clock")
            self.assertIsInstance(evs[3].result, RunResult)
        finally:
            s.close()
        err = b'event: error\ndata: {"error":{"code":"OVERLOADED","message":"busy"}}\n\n'
        s = Stub([(200, {}, err)])
        try:
            with self.assertRaises(SandboxdError) as e:
                list(Sandboxd(s.url, "t").stream("1"))
            self.assertEqual(e.exception.code, "OVERLOADED")
        finally:
            s.close()

    def test_repr_hides_token(self):
        self.assertNotIn("secret", repr(Sandboxd("http://x", "secret")))


HAVE_SERVER = bool(os.environ.get("SANDBOXD_URL"))
if not HAVE_SERVER and os.environ.get("SANDBOXD_REQUIRE_SERVER") == "1":
    raise RuntimeError("SANDBOXD_REQUIRE_SERVER=1 but SANDBOXD_URL is not set")


@unittest.skipUnless(HAVE_SERVER, "needs a server (run through clients/testserver.py)")
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.c = Sandboxd()

    def test_health_and_policies(self):
        self.assertEqual(self.c.health()["status"], "ok")
        names = {p.name for p in self.c.policies()}
        self.assertTrue({"default", "notebook"} <= names, names)

    def test_run_files_args_stdin_artifacts(self):
        code = ("import sys, os\n"
                "data = open('/in/data/n.txt').read().split()\n"
                "raw = open('/in/raw.bin', 'rb').read()\n"
                "open('/out/sum.txt', 'w').write(str(sum(map(int, data))))\n"
                "open('/out/raw.bin', 'wb').write(raw[::-1])\n"
                "print(sys.argv[1:], sys.stdin.read().strip())\n")
        r = self.c.run(code, files={"data/n.txt": "1 2 3", "raw.bin": b"\x01\x02\xff"},
                       args=["a", "b"], stdin="hello\n")
        self.assertTrue(r.ok, r)
        self.assertEqual(r.stdout, "['a', 'b'] hello\n")
        self.assertEqual(r.artifact("sum.txt").text(), "6")
        self.assertEqual(r.artifact("raw.bin").content, b"\xff\x02\x01")

    def test_javascript(self):
        r = self.c.run("console.log(6 * 7)", "javascript")
        self.assertEqual((r.ok, r.stdout), (True, "42\n"))

    def test_guest_failures_are_results(self):
        r = self.c.run("raise SystemExit(3)")
        self.assertEqual((r.ok, r.outcome, r.exit_code), (False, "exit", 3))
        r = self.c.run("1/0")
        self.assertFalse(r.ok)
        self.assertIn("ZeroDivisionError", r.stderr)
        r = self.c.run("while True: pass", limits={"wall_clock": "1s"})
        self.assertEqual(r.outcome, "limit")
        self.assertIn("wall_clock", r.limits_hit)

    def test_stream(self):
        evs = list(self.c.stream("import sys\nprint('out')\nprint('err', file=sys.stderr)"))
        self.assertEqual(evs[-1].type, "result")
        self.assertTrue(evs[-1].result.ok)
        self.assertIn("out\n", "".join(e.text for e in evs if e.type == "stdout"))
        self.assertIn("err\n", "".join(e.text for e in evs if e.type == "stderr"))

    def test_session(self):
        with self.c.create_session(policy="notebook") as s:
            self.assertEqual(s.last_info.state, "active")
            self.assertTrue(s.run("x = 41").ok)
            self.assertEqual(s.run("print(x + 1)").stdout, "42\n")
            evs = list(s.stream("print(x * 2)"))
            self.assertEqual(evs[-1].result.stdout, "82\n")
            self.assertEqual(s.info().calls, 3)
            sid = s.id
        with self.assertRaises(SandboxdError) as e:
            self.c.session(sid).run("print(x)")
        self.assertEqual(e.exception.code, "SESSION_NOT_FOUND")

    def test_refusals(self):
        with self.assertRaises(SandboxdError) as e:
            Sandboxd(token="wrong").run("1")
        self.assertEqual((e.exception.code, e.exception.status), ("UNAUTHORIZED", 401))
        with self.assertRaises(SandboxdError) as e:
            self.c.run("1", policy="no-such-policy")
        self.assertEqual((e.exception.code, e.exception.status), ("POLICY_NOT_FOUND", 404))
        with self.assertRaises(SandboxdError) as e:
            self.c.run("1", limits={"wall_clock": "soon"})
        self.assertEqual((e.exception.code, e.exception.status), ("INVALID_REQUEST", 400))
        with self.assertRaises(SandboxdError) as e:
            self.c.create_session(policy="default")
        self.assertEqual(e.exception.code, "SESSIONS_DISABLED")


if __name__ == "__main__":
    unittest.main()
