# sandboxd-client (JavaScript / TypeScript)

Client for [sandboxd](https://github.com/SoumyabrataNandi/Agent_SandBox), the WebAssembly sandbox
for code written by AI agents. One ES module on `fetch`, no dependencies, with TypeScript types.
Runs on Node ≥ 18, Deno, Bun and in browsers.

## Install

The package is attached to each GitHub release:

```bash
npm install https://github.com/SoumyabrataNandi/Agent_SandBox/releases/download/v0.3.0/sandboxd-client-0.3.0.tgz
```

## Use

```js
import { Sandboxd, SandboxdError } from "sandboxd-client";

const sbx = new Sandboxd({ url: "http://127.0.0.1:8080", token: "sbx_..." }); // or SANDBOXD_URL / SANDBOXD_TOKEN

const r = await sbx.run("print(6*7)");
console.log(r.ok, r.stdout); // true "42\n"

// Files are read-only under /in (strings or Uint8Array); files written to /out come back as artifacts.
const csv = await sbx.run(
  "import csv\nrows = list(csv.reader(open('/in/data.csv')))\nopen('/out/count.txt', 'w').write(str(len(rows)))",
  { files: { "data.csv": "a,b\n1,2\n" }, limits: { wall_clock: "5s", memory: "128MiB" } },
);
console.log(csv.artifact("count.txt").text()); // "2"

// JavaScript
console.log((await sbx.run("console.log([1, 2, 3].map(x => x * 2))", { language: "javascript" })).stdout);

// Streaming: stdout/stderr/limit events as they happen, then the result.
for await (const ev of sbx.stream("for i in range(3): print(i, flush=True)")) {
  if (ev.type === "stdout") process.stdout.write(ev.text);
  else if (ev.type === "result") console.log("done:", ev.result.outcome);
}

// Sessions keep variables, imports and /work between runs (the policy must enable sessions).
{
  await using s = await sbx.createSession({ policy: "notebook" }); // closed at the end of the block
  await s.run("import json\nrows = [1, 2, 3]");
  console.log((await s.run("print(sum(rows))")).stdout); // "6\n"
}
```

Without `await using` (older runtimes), call `await s.close()` in a `finally`.

## Results and errors

- A failure **inside** the sandbox is a normal result: `r.ok` is false and `r.outcome` is `exit`, `limit`, `trap` or `error`; `r.exitCode`, `r.stderr`, `r.limitsHit` and `r.error` say why.
- `SandboxdError` is thrown when the server refuses the request. Its `code` is the server's code (`UNAUTHORIZED`, `POLICY_NOT_FOUND`, `INVALID_REQUEST`, `SESSION_NOT_FOUND`, `SESSIONS_DISABLED`, ...) or `UNREACHABLE`, and `status` is the HTTP status.
- `429` answers (`OVERLOADED`, `SESSION_LIMIT`) are retried up to `retries` times (default 3), waiting as long as `Retry-After` says (at most 10 s).

## Options

`new Sandboxd({ url, token, timeoutMs = 300000, retries = 3, fetch, userAgent })`. For streams,
`timeoutMs` covers the wait for the response headers. The run itself is bounded by its `wall_clock` limit.

## Tests

```bash
node --test clients/js/test/client.test.js                              # unit tests only
python clients/testserver.py --sandboxd target/debug/sandboxd -- \
       node --test clients/js/test/client.test.js                       # + a real server
```
