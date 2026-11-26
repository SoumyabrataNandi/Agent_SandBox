// Tests for sandboxd-client (cycle 6, FR-CL1.7). Unit tests use a stub HTTP server. Integration
// tests need a real server: run them through clients/testserver.py, which sets SANDBOXD_URL /
// SANDBOXD_TOKEN. Without those they are skipped, unless SANDBOXD_REQUIRE_SERVER=1 (CI).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Sandboxd, SandboxdError } from "../index.js";

function stub(replies) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const [status, headers, payload] = replies.shift();
      const data = typeof payload === "string" ? payload : JSON.stringify(payload);
      res.writeHead(status, { "Content-Length": Buffer.byteLength(data), ...headers });
      res.end(data);
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ url: `http://127.0.0.1:${server.address().port}`, requests, close: () => server.close() }),
    ),
  );
}

const RESULT = {
  run_id: "r1", language: "python", policy: "default", outcome: "ok", exit_code: 0,
  stdout: "42\n", stderr: "", stdout_truncated: false, stderr_truncated: false,
  artifacts: [{ name: "a.txt", size: 2, sha256: "x", content_base64: Buffer.from("hi").toString("base64") }],
  limits_hit: [], error: null, fuel_used: 10, peak_memory: 20,
  timings: { queued_ms: 0, setup_ms: 1, run_ms: 2, collect_ms: 0, total_ms: 3 },
};

describe("unit", () => {
  test("headers, body and result", async () => {
    const s = await stub([[200, { "Content-Type": "application/json" }, RESULT]]);
    try {
      const r = await new Sandboxd({ url: s.url, token: "tok" }).run("print(6*7)", {
        files: { "t.txt": "x", "b.bin": new Uint8Array([0, 255]) },
        limits: { wall_clock: "2s" },
      });
      const req = s.requests[0];
      assert.equal(req.method, "POST");
      assert.equal(req.url, "/v1/runs");
      assert.equal(req.headers["content-type"], "application/json");
      assert.equal(req.headers.authorization, "Bearer tok");
      const sent = JSON.parse(req.body);
      assert.deepEqual(sent.files[0], { name: "t.txt", content: "x" });
      assert.equal(sent.files[1].encoding, "base64");
      assert.deepEqual([...Buffer.from(sent.files[1].content, "base64")], [0, 255]);
      assert.equal(sent.stdin, undefined);
      assert.equal(r.ok, true);
      assert.equal(r.stdout, "42\n");
      assert.equal(r.artifact("a.txt").text(), "hi");
      assert.equal(r.timings.totalMs, 3);
    } finally {
      s.close();
    }
  });

  test("no token, no Authorization header", async () => {
    const s = await stub([[200, {}, { status: "ok" }]]);
    try {
      assert.deepEqual(await new Sandboxd({ url: s.url, token: "" }).health(), { status: "ok" });
      assert.equal(s.requests[0].headers.authorization, undefined);
    } finally {
      s.close();
    }
  });

  test("error mapping", async () => {
    const s = await stub([
      [404, {}, { error: { code: "POLICY_NOT_FOUND", message: "no policy 'x'" } }],
      [502, {}, "bad gateway"],
    ]);
    try {
      const c = new Sandboxd({ url: s.url, token: "t" });
      await assert.rejects(c.run("1", { policy: "x" }), (e) => e instanceof SandboxdError && e.code === "POLICY_NOT_FOUND" && e.status === 404);
      await assert.rejects(c.run("1"), (e) => e.code === "HTTP_502" && e.status === 502);
    } finally {
      s.close();
    }
  });

  test("retries 429", async () => {
    const busy = [429, { "Retry-After": "0" }, { error: { code: "OVERLOADED", message: "busy" } }];
    let s = await stub([busy, busy, [200, {}, RESULT]]);
    try {
      assert.equal((await new Sandboxd({ url: s.url, token: "t" }).run("1")).ok, true);
      assert.equal(s.requests.length, 3);
    } finally {
      s.close();
    }
    s = await stub([busy, busy]);
    try {
      await assert.rejects(new Sandboxd({ url: s.url, token: "t", retries: 1 }).run("1"), (e) => e.code === "OVERLOADED");
    } finally {
      s.close();
    }
  });

  test("unreachable", async () => {
    await assert.rejects(new Sandboxd({ url: "http://127.0.0.1:9", token: "t", timeoutMs: 2000 }).health(), (e) => e.code === "UNREACHABLE");
  });

  test("stream parsing", async () => {
    const sse =
      ": keep-alive\n\n" +
      'event: stdout\ndata: {"text":"a\\n"}\n\n' +
      'event: stderr\ndata: {"text":"?","base64":"/w=="}\n\n' +
      "event: future\ndata: {}\n\n" +
      'event: limit\ndata: {"kind":"wall_clock"}\n\n' +
      `event: result\ndata: ${JSON.stringify(RESULT)}\n\n`;
    let s = await stub([[200, { "Content-Type": "text/event-stream" }, sse]]);
    try {
      const evs = [];
      for await (const ev of new Sandboxd({ url: s.url, token: "t" }).stream("print('a')")) evs.push(ev);
      assert.equal(s.requests[0].url, "/v1/runs?stream=true");
      assert.deepEqual(evs.map((e) => e.type), ["stdout", "stderr", "limit", "result"]);
      assert.equal(evs[0].text, "a\n");
      assert.deepEqual([...evs[1].data], [255]);
      assert.equal(evs[2].limit, "wall_clock");
      assert.equal(evs[3].result.ok, true);
    } finally {
      s.close();
    }
    s = await stub([[200, {}, 'event: error\ndata: {"error":{"code":"OVERLOADED","message":"busy"}}\n\n']]);
    try {
      await assert.rejects(async () => {
        for await (const _ of new Sandboxd({ url: s.url, token: "t" }).stream("1"));
      }, (e) => e.code === "OVERLOADED");
    } finally {
      s.close();
    }
  });

  test("the token is not serialised", () => {
    assert.ok(!JSON.stringify(new Sandboxd({ url: "http://x", token: "secret" })).includes("secret"));
  });
});

const HAVE_SERVER = !!process.env.SANDBOXD_URL;
if (!HAVE_SERVER && process.env.SANDBOXD_REQUIRE_SERVER === "1") {
  throw new Error("SANDBOXD_REQUIRE_SERVER=1 but SANDBOXD_URL is not set");
}

describe("integration", { skip: !HAVE_SERVER && "needs a server (run through clients/testserver.py)" }, () => {
  const c = new Sandboxd();

  test("health and policies", async () => {
    assert.equal((await c.health()).status, "ok");
    const names = (await c.policies()).map((p) => p.name);
    assert.ok(names.includes("default") && names.includes("notebook"), names.join());
  });

  test("run with files, args, stdin and artifacts", async () => {
    const code =
      "import sys\n" +
      "data = open('/in/data/n.txt').read().split()\n" +
      "raw = open('/in/raw.bin', 'rb').read()\n" +
      "open('/out/sum.txt', 'w').write(str(sum(map(int, data))))\n" +
      "open('/out/raw.bin', 'wb').write(raw[::-1])\n" +
      "print(sys.argv[1:], sys.stdin.read().strip())\n";
    const r = await c.run(code, {
      files: { "data/n.txt": "1 2 3", "raw.bin": new Uint8Array([1, 2, 255]) },
      args: ["a", "b"],
      stdin: "hello\n",
    });
    assert.equal(r.ok, true, JSON.stringify(r.raw));
    assert.equal(r.stdout, "['a', 'b'] hello\n");
    assert.equal(r.artifact("sum.txt").text(), "6");
    assert.deepEqual([...r.artifact("raw.bin").content], [255, 2, 1]);
  });

  test("javascript", async () => {
    const r = await c.run("console.log(6 * 7)", { language: "javascript" });
    assert.equal(r.ok, true);
    assert.equal(r.stdout, "42\n");
  });

  test("guest failures are results", async () => {
    let r = await c.run("raise SystemExit(3)");
    assert.deepEqual([r.ok, r.outcome, r.exitCode], [false, "exit", 3]);
    r = await c.run("1/0");
    assert.equal(r.ok, false);
    assert.match(r.stderr, /ZeroDivisionError/);
    r = await c.run("while True: pass", { limits: { wall_clock: "1s" } });
    assert.equal(r.outcome, "limit");
    assert.ok(r.limitsHit.includes("wall_clock"));
  });

  test("stream", async () => {
    const evs = [];
    for await (const ev of c.stream("import sys\nprint('out')\nprint('err', file=sys.stderr)")) evs.push(ev);
    const last = evs.at(-1);
    assert.equal(last.type, "result");
    assert.equal(last.result.ok, true);
    assert.match(evs.filter((e) => e.type === "stdout").map((e) => e.text).join(""), /out\n/);
    assert.match(evs.filter((e) => e.type === "stderr").map((e) => e.text).join(""), /err\n/);
  });

  test("session", async () => {
    const s = await c.createSession({ policy: "notebook" });
    try {
      assert.equal(s.lastInfo.state, "active");
      assert.equal((await s.run("x = 41")).ok, true);
      assert.equal((await s.run("print(x + 1)")).stdout, "42\n");
      let last;
      for await (const ev of s.stream("print(x * 2)")) last = ev;
      assert.equal(last.result.stdout, "82\n");
      assert.equal((await s.info()).calls, 3);
    } finally {
      await s.close();
    }
    await assert.rejects(c.session(s.id).run("print(x)"), (e) => e.code === "SESSION_NOT_FOUND");
  });

  test("refusals", async () => {
    await assert.rejects(new Sandboxd({ token: "wrong" }).run("1"), (e) => e.code === "UNAUTHORIZED" && e.status === 401);
    await assert.rejects(c.run("1", { policy: "no-such-policy" }), (e) => e.code === "POLICY_NOT_FOUND" && e.status === 404);
    await assert.rejects(c.run("1", { limits: { wall_clock: "soon" } }), (e) => e.code === "INVALID_REQUEST" && e.status === 400);
    await assert.rejects(c.createSession({ policy: "default" }), (e) => e.code === "SESSIONS_DISABLED");
  });
});
