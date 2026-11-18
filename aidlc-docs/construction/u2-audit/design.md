# U2 Audit — Functional, NFR & Infrastructure Design

## 1. Event model
Each line is one JSON object. The common envelope:
```json
{"ts":"2026-11-18T19:22:41.123Z","v":1,"event":"run.start","run_id":"0193…(uuid v7)","policy":"default","principal":"ci-bot", …event fields}
```
| `event` | Fields |
|---|---|
| `run.start` | `lang`, `code_sha256`, `code_bytes`, `code` (only if `log_code`; redacted, max 64KiB), `inputs` [{name, bytes, sha256}] |
| `run.end` | `outcome` (`ok`/`exit`/`limit`/`trap`/`error`), `exit_code`, `duration_ms`, `fuel_used`, `peak_memory`, `limits_hit[]`, `stdout_bytes`, `stderr_bytes`, `artifacts` [{name, bytes, sha256}] |
| `fs.access` | `op` (open/stat/mkdir/unlink/rename/readlink/…), `path` (guest path), `mode`, `decision` (`allow`/`deny`), `reason` |
| `env.read` | `key`, `decision`. Values are never logged. |
| `limit.hit` | `kind` (`cpu`/`wall_clock`/`memory`/`stdout`/`stderr`/`artifacts`/`inputs`), `limit`, `observed` |
| `policy.denied` | `what` (e.g. `override would widen limits.memory`), `requested` |
| `net.request` | *Reserved for Phase 4:* `proto`, `host`, `ip`, `port`, `method`, `path`, `status`, `bytes_out`, `bytes_in`, `decision` |
| `audit.dropped` | `count` (events lost because the queue was full since the last report) |
| `server.start` / `server.stop` | `version`, `asset_pins`, `policies[]` |

`fs.access` was renamed from `fs.open` because it covers every path operation in ADR-001.

## 2. Components
```rust
pub trait AuditSink: Send + Sync + 'static { fn emit(&self, ev: AuditEvent); }   // non-blocking, infallible to callers
pub struct JsonlSink;      // bounded queue → writer thread → BufWriter<File|Stdout>
pub struct FanoutSink;     // Vec<Arc<dyn AuditSink>>
pub struct MemorySink;     // test helper: collects events (pub, behind `testing` feature)
pub struct NullSink;
pub struct Redactor;       // applied by JsonlSink before serialization
pub struct AuditEvent { pub ts: SystemTime, pub run_id: Option<RunId>, pub policy: Option<String>, pub principal: Option<String>, pub kind: EventKind }
pub enum EventKind { RunStart{..}, RunEnd{..}, FsAccess{..}, EnvRead{..}, LimitHit{..}, PolicyDenied{..}, NetRequest{..}, Dropped{count}, ServerStart{..}, ServerStop }
pub struct RunId(uuid::Uuid);   // v7: time-ordered, so logs sort naturally
```
`RunId` lives here because audit is a leaf crate and every other crate already depends on it.

## 3. Rules
| ID | Rule |
|---|---|
| A1 | `emit` never blocks and never fails. If the queue (default 8192) is full, the event is dropped and counted, and an `audit.dropped` event is written at the next opportunity. |
| A2 | The writer thread drains in batches and flushes after each drained batch (Q5). |
| A3 | Redaction runs on every free-text field (`code`, `reason`, `what`, `path`, and the later `net.*` fields). Built-in patterns: `Bearer <tok>`, `sk-…`/`sk-ant-…`, `ghp_/gho_/github_pat_…`, `AKIA[0-9A-Z]{16}`, JWT (`eyJ…\.…\.…`), `xox[bp]-…`, PEM private-key blocks, and `password|passwd|secret|token|api_key = value`. Operators can add regexes in config. A match is replaced with `[REDACTED:<kind>]`. |
| A4 | Every string field is truncated to 4KiB except `code` (64KiB); truncated fields are marked `"…[truncated N bytes]"`. |
| A5 | API tokens are never logged. `principal` is the configured token *name*, or `token:<first 12 hex of sha256>`. |
| A6 | `shutdown()` (also called on Drop) drains the queue and flushes within 2s. `server.stop` is the last line. |
| A7 | File sinks open in append mode and create the file if missing. Unix permissions are 0600; on Windows the file inherits the directory ACL (documented). |

## 4. NFR (scaled)
- **Performance:** `emit` should cost under 1µs plus a channel send. Serialization and redaction happen on the writer thread, not the guest's.
- **Reliability:** if a write fails (disk full), the sink reports it on stderr once per minute, keeps counting drops, and never panics or stops runs. Whether runs should *fail closed* when audit is broken is Q6.
- **Security:** `#![forbid(unsafe_code)]`. Redaction is tested against a corpus of real-looking fake secrets.
- **Testing:** golden JSON for every event kind; redaction corpus; backpressure test (queue size 1 → drops counted and reported); shutdown-flush test.

## 5. Infrastructure
No infrastructure. Dependencies: `serde`, `serde_json`, `uuid` (v7), `regex`, `sha2`, `hex`, `humantime` (RFC 3339 ms timestamps only). The OTLP exporter depends on Q4.
