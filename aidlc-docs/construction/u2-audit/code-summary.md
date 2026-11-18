# U2 Audit — Code Summary & Test Results (2026-11-18)

Design answers: Q4 OTLP moves to U5, Q5 batch flush, Q6 fail closed, Q7 external rotation (all A).

| File | Content |
|---|---|
| `src/event.rs` | `AuditEvent` envelope (ts RFC 3339 ms, `v`, run_id, policy, principal) + flattened `EventKind` (10 kinds). `RunId` (UUID v7), `LimitKind`, `Outcome`, `FsOp`, `Decision`, `FileDigest`. Truncation (4 KiB / 64 KiB code), `sha256_hex`, `token_principal` |
| `src/redact.rs` | `Redactor`: 9 built-in patterns (PEM, bearer, Anthropic, sk-, GitHub, AWS, JWT, Slack, key=value) + operator patterns |
| `src/sink.rs` | `AuditSink` trait with `is_healthy()` (fail-closed signal); `JsonlSink` (bounded queue → writer thread, batch flush, drop counting → `audit.dropped`, pending-retry while failing, 0600 on Unix, idempotent `shutdown` with timeout); `FanoutSink`, `NullSink`, `MemorySink` (feature `testing`) |

**Tests:** 12 (3 unit + 9 integration). Covered: golden JSON envelope, every event name, redaction and truncation, token never logged, 500-event flush on shutdown, "written + counted drops == emitted" under backpressure, health false on write failure then recovery with the pending line written, file append across reopen, fan-out health.

**Deviation:** `fs.open` was renamed to `fs.access` because it covers all path operations, as recorded in the design.
