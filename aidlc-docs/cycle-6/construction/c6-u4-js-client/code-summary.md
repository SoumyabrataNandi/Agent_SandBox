# C6-U4 JavaScript client — Summary

**Requirements:** FR-CL1, FR-CL2 · **AC:** 1, 3

- **`clients/js` (`sandboxd-client`, ES module, no dependencies; Node ≥ 18, Deno, Bun, browsers):**
  - `new Sandboxd({url, token, timeoutMs, retries, fetch, userAgent})`. The token is a private field; `toJSON` shows only the URL.
  - `run` and `stream` (an async generator of `{type: stdout|stderr|limit|result}`).
  - `createSession` / `session(id)` return a `Session` with `run`, `stream`, `info`, `close` and `[Symbol.asyncDispose]` (`await using`).
  - `policies`, `health`.
  - Results use camelCase names, with `ok`, `artifact(name)`, `Uint8Array` contents and `raw`.
- **Errors:** `SandboxdError` with `code`, `status` and `detail`. `fetch` failures and timeouts map to `UNREACHABLE`. `429` is retried with `Retry-After`. For streams, `timeoutMs` covers only the wait for the response headers.
- **Types:** hand-written `index.d.ts`, checked by `clients/js/test/types.ts` with `tsc --strict` (TypeScript 5.9.3).
- **Tests (`node --test`):** the same 7 unit and 7 integration tests as the Python client. Local: 14/14 on Node 26 against a real server; the README example runs as written. CI runs them on Node 18.
- **Packaging:** `npm pack` ships `index.js`, `index.d.ts`, `package.json` and `README.md`.
- **CI (`ci.yml` job `clients`):** version check; debug `sandboxd`; the Python 3.10 and Node 18 suites through `testserver.py` with `SANDBOXD_REQUIRE_SERVER=1`; `tsc`; wheel and npm pack build.
- **Release (`release.yml` job `clients`):** checks the versions against the tag, builds the wheel and tarball, attests them and adds them to the draft release, with `SHA256SUMS`. The release notes show both install commands.
