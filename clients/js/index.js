// JavaScript client for the sandboxd HTTP API (cycle 6, FR-CL1). No dependencies: it uses
// `fetch`, so it runs on Node >= 18, Deno, Bun and in browsers.
//
//   import { Sandboxd } from "sandboxd-client";
//   const sbx = new Sandboxd({ url: "http://127.0.0.1:8080", token: "sbx_..." });
//   const r = await sbx.run("print(6*7)");
//   console.log(r.stdout); // "42\n"
//
// A guest failure (an exception, a non-zero exit, a limit) is a normal result (`r.ok` is false);
// `SandboxdError` is thrown only when the server refuses a request.

export const VERSION = "0.2.1";
const DEFAULT_URL = "http://127.0.0.1:8080";
const MAX_RETRY_WAIT_MS = 10_000;

/** The server refused a request (or could not be reached). */
export class SandboxdError extends Error {
  constructor(code, message, status = null) {
    super(status == null ? `${code}: ${message}` : `${code} (${status}): ${message}`);
    this.name = "SandboxdError";
    this.code = code;
    this.status = status;
    this.detail = message;
  }
}

const env = (name) => {
  try {
    return globalThis.process?.env?.[name] || globalThis.Deno?.env?.get(name) || undefined;
  } catch {
    return undefined; // Deno without --allow-env
  }
};

function toBase64(bytes) {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromBase64(b64) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const utf8 = (s) => new TextEncoder().encode(s);

function encodeFiles(files) {
  if (!files) return undefined;
  const entries = Array.isArray(files) ? files : Object.entries(files);
  if (entries.length === 0) return undefined;
  return entries.map(([name, content]) => {
    if (typeof content === "string") return { name, content };
    const bytes = content instanceof Uint8Array ? content : new Uint8Array(content);
    return { name, content: toBase64(bytes), encoding: "base64" };
  });
}

function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

function runResult(d) {
  const bytes = (text, b64) => (b64 ? fromBase64(b64) : utf8(text ?? ""));
  const artifacts = (d.artifacts ?? []).map((a) => {
    const content = fromBase64(a.content_base64);
    return { name: a.name, size: a.size, sha256: a.sha256, content, text: () => new TextDecoder().decode(content) };
  });
  return {
    runId: d.run_id,
    language: d.language,
    policy: d.policy,
    outcome: d.outcome,
    ok: d.outcome === "ok",
    exitCode: d.exit_code ?? null,
    stdout: d.stdout ?? "",
    stderr: d.stderr ?? "",
    stdoutBytes: bytes(d.stdout, d.stdout_base64),
    stderrBytes: bytes(d.stderr, d.stderr_base64),
    stdoutTruncated: !!d.stdout_truncated,
    stderrTruncated: !!d.stderr_truncated,
    artifacts,
    artifact(name) {
      const a = artifacts.find((x) => x.name === name);
      if (!a) throw new Error(`no artifact named ${name}`);
      return a;
    },
    limitsHit: d.limits_hit ?? [],
    error: d.error ?? null,
    fuelUsed: d.fuel_used ?? 0,
    peakMemory: d.peak_memory ?? 0,
    timings: {
      queuedMs: d.timings?.queued_ms ?? 0,
      setupMs: d.timings?.setup_ms ?? 0,
      runMs: d.timings?.run_ms ?? 0,
      collectMs: d.timings?.collect_ms ?? 0,
      totalMs: d.timings?.total_ms ?? 0,
    },
    sessionId: d.session_id ?? null,
    sessionEnded: d.session_ended ?? null,
    raw: d,
  };
}

function sessionInfo(d) {
  return {
    sessionId: d.session_id,
    language: d.language,
    policy: d.policy,
    interpreter: d.interpreter,
    state: d.state,
    endedReason: d.ended_reason ?? null,
    calls: d.calls,
    maxCalls: d.max_calls,
    createdAt: d.created_at,
    expiresAt: d.expires_at,
    idleTimeoutS: d.idle_timeout_s,
  };
}

async function errorFrom(resp) {
  const text = await resp.text().catch(() => "");
  try {
    const e = JSON.parse(text).error;
    if (e && e.code) return new SandboxdError(String(e.code), String(e.message ?? ""), resp.status);
  } catch {
    /* not JSON */
  }
  return new SandboxdError(`HTTP_${resp.status}`, text.trim() || resp.statusText || "request failed", resp.status);
}

function retryWaitMs(header, attempt) {
  const s = Number(header);
  const ms = header != null && header !== "" && Number.isFinite(s) ? s * 1000 : 500 * attempt;
  return Math.max(0, Math.min(ms, MAX_RETRY_WAIT_MS));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Parse server-sent events from a fetch body. */
async function* events(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let name = "message";
  let data = [];
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).replace(/\r$/, "");
        buf = buf.slice(nl + 1);
        if (line === "") {
          if (data.length) {
            const ev = toEvent(name, JSON.parse(data.join("\n")));
            if (ev) {
              yield ev;
              if (ev.type === "result") return;
            }
          }
          name = "message";
          data = [];
          continue;
        }
        if (line.startsWith(":")) continue; // keep-alive comment
        const i = line.indexOf(":");
        const key = i < 0 ? line : line.slice(0, i);
        let val = i < 0 ? "" : line.slice(i + 1);
        if (val.startsWith(" ")) val = val.slice(1);
        if (key === "event") name = val;
        else if (key === "data") data.push(val);
      }
    }
  } finally {
    reader.releaseLock?.();
    body.cancel?.().catch(() => {});
  }
  throw new SandboxdError("STREAM_ENDED", "the stream ended without a result");
}

function toEvent(name, d) {
  if (name === "stdout" || name === "stderr") {
    const text = d.text ?? "";
    return { type: name, text, data: d.base64 ? fromBase64(d.base64) : utf8(text) };
  }
  if (name === "limit") return { type: "limit", limit: d.kind };
  if (name === "result") return { type: "result", result: runResult(d) };
  if (name === "error") {
    const e = d.error ?? {};
    throw new SandboxdError(String(e.code ?? "ERROR"), String(e.message ?? ""));
  }
  return null; // unknown event types are ignored (forward compatibility)
}

/** A persistent sandbox: variables, imports and /work carry over between runs. */
export class Session {
  constructor(client, id, info = null) {
    this.client = client;
    this.id = id;
    this.lastInfo = info;
  }

  #path(suffix = "") {
    return `/v1/sessions/${encodeURIComponent(this.id)}${suffix}`;
  }

  /** Run one cell. `limits` may tighten `wall_clock` and `fuel` for this call only. */
  async run(code, opts = {}) {
    const body = compact({ code, files: encodeFiles(opts.files), args: opts.args, limits: opts.limits });
    return runResult(await this.client._json("POST", this.#path("/runs"), body));
  }

  /** Run one cell, yielding output as it is produced; the last event is the result. */
  stream(code, opts = {}) {
    const body = compact({ code, files: encodeFiles(opts.files), args: opts.args, limits: opts.limits });
    return this.client._stream(this.#path("/runs"), body);
  }

  async info() {
    this.lastInfo = sessionInfo(await this.client._json("GET", this.#path()));
    return this.lastInfo;
  }

  async close() {
    this.lastInfo = sessionInfo(await this.client._json("DELETE", this.#path()));
    return this.lastInfo;
  }

  /** `await using s = await sbx.createSession(...)` closes the session at the end of the scope. */
  async [Symbol.asyncDispose ?? Symbol.for("Symbol.asyncDispose")]() {
    try {
      await this.close();
    } catch (e) {
      if (!(e instanceof SandboxdError && e.code === "SESSION_NOT_FOUND")) throw e;
    }
  }
}

/** A sandboxd server. */
export class Sandboxd {
  #token;

  /**
   * @param {object} [opts]
   * @param {string} [opts.url]  default: $SANDBOXD_URL, then http://127.0.0.1:8080
   * @param {string} [opts.token] default: $SANDBOXD_TOKEN
   * @param {number} [opts.timeoutMs] per request (until the response headers for streams); default 300000
   * @param {number} [opts.retries] retries for 429 answers; default 3
   * @param {typeof fetch} [opts.fetch] custom fetch implementation
   */
  constructor(opts = {}) {
    this.url = (opts.url ?? env("SANDBOXD_URL") ?? DEFAULT_URL).replace(/\/+$/, "");
    this.#token = opts.token !== undefined ? opts.token || undefined : env("SANDBOXD_TOKEN");
    this.timeoutMs = opts.timeoutMs ?? 300_000;
    this.retries = opts.retries ?? 3;
    this.fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.userAgent = opts.userAgent ?? `sandboxd-client-js/${VERSION}`;
  }

  toJSON() {
    return { url: this.url }; // never serialise the token
  }

  /** Run code in a fresh sandbox. */
  async run(code, opts = {}) {
    return runResult(await this._json("POST", "/v1/runs", runBody(code, opts)));
  }

  /** Like `run`, but yields stdout/stderr/limit events as they happen; the last one is the result. */
  stream(code, opts = {}) {
    return this._stream("/v1/runs", runBody(code, opts));
  }

  /** Start a persistent session. The policy must enable sessions. */
  async createSession(opts = {}) {
    const body = compact({
      language: opts.language ?? "python",
      policy: opts.policy,
      files: encodeFiles(opts.files),
      limits: opts.limits,
    });
    const info = sessionInfo(await this._json("POST", "/v1/sessions", body));
    return new Session(this, info.sessionId, info);
  }

  /** Attach to an existing session by id. */
  session(id) {
    return new Session(this, id);
  }

  async policies() {
    const d = await this._json("GET", "/v1/policies");
    return (d.policies ?? []).map((p) => ({
      name: p.name,
      description: p.description ?? "",
      overridesBuiltin: !!p.overrides_builtin,
      wallClock: p.wall_clock ?? "",
      memory: p.memory ?? "",
      mounts: p.mounts ?? [],
    }));
  }

  /** `{ status: "ok" }` when ready; throws SandboxdError otherwise. */
  async health() {
    return this._json("GET", "/healthz");
  }

  async _send(method, path, body, accept, streaming) {
    const headers = { Accept: accept };
    if (typeof window === "undefined") headers["User-Agent"] = this.userAgent;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.#token) headers.Authorization = `Bearer ${this.#token}`;
    for (let attempt = 0; ; attempt++) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      let resp;
      try {
        resp = await this.fetch(this.url + path, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: ctl.signal,
        });
      } catch (e) {
        clearTimeout(timer);
        const why = ctl.signal.aborted ? `timed out after ${this.timeoutMs} ms` : e?.cause?.message ?? e?.message ?? String(e);
        throw new SandboxdError("UNREACHABLE", `${this.url}: ${why}`);
      }
      if (streaming) clearTimeout(timer); // the stream itself may run as long as the server allows
      try {
        if (resp.ok) return { resp, timer };
        const err = await errorFrom(resp);
        if (resp.status === 429 && attempt < this.retries) {
          await sleep(retryWaitMs(resp.headers.get("Retry-After"), attempt + 1));
          continue;
        }
        throw err;
      } finally {
        if (!resp.ok || streaming) clearTimeout(timer);
      }
    }
  }

  async _json(method, path, body) {
    const { resp, timer } = await this._send(method, path, body, "application/json", false);
    try {
      const text = await resp.text();
      return text ? JSON.parse(text) : {};
    } finally {
      clearTimeout(timer);
    }
  }

  async *_stream(path, body) {
    const { resp } = await this._send("POST", `${path}?stream=true`, body, "text/event-stream", true);
    yield* events(resp.body);
  }
}

function runBody(code, opts) {
  return compact({
    language: opts.language ?? "python",
    code,
    policy: opts.policy,
    files: encodeFiles(opts.files),
    args: opts.args,
    stdin: opts.stdin,
    limits: opts.limits,
  });
}
