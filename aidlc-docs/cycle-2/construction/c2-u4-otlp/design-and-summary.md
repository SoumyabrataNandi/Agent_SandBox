# C2-U4 OTLP Exporter — Design & Code Summary (combined gate)

**Requirement:** FR-O1 (O1.1–O1.3) · **ADR:** ADR-C2-6 · **Depends on:** C2-U1 (config), C2-U3 (`RunResult.net_requests`)

## Design
| Decision | Choice | Why |
|---|---|---|
| Crates | `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` **0.33**, `default-features = false`, OTLP/HTTP **protobuf** (`http-proto`), `reqwest-blocking-client` | opentelemetry-otlp 0.33 uses **reqwest 0.13**, the same HTTP/TLS stack as the network broker: no second client, no new TLS crates. Only prost and the OTel crates are added, and only with the feature. |
| Feature | `sandboxd-server/otel`, re-exported as `sandboxd/otel`; **off by default** | The default build compiles **no** OpenTelemetry or prost crate (CI-checked with `cargo tree`). |
| Config | `[telemetry] otlp_endpoint` (base URL; `/v1/metrics` and `/v1/traces` are appended; `http(s)://` only, validated at load) and `otlp_interval` (default 30s, 1s–1h). Standard `OTEL_EXPORTER_OTLP_*` env vars, such as headers, are still honoured by the exporter. | Cycle 1 reserved the key. An endpoint on a build without the feature → warning, no export. |
| Metrics | Each Prometheus record point also updates an OTel instrument: `sandboxd.runs` {language, policy, outcome}, `sandboxd.run.duration` (s, same buckets) {language}, `sandboxd.limits_hit` {kind}, `sandboxd.rejected` {reason}, `sandboxd.queue_depth`, `sandboxd.running`, `sandboxd.audit_healthy`, `sandboxd.startup` (ms) | O1.1 "same counters and histograms as /metrics". The instruments come from the global meter: no-ops until `Telemetry::init` installs a provider, so the run path has no feature plumbing. |
| Span | `sandboxd.run` per completed run. Start = request received; end = start + `total_ms`. Attributes: `run_id`, `language`, `policy`, `outcome`, `limits_hit` (string array), `exit_code`, `error` (code only), `fuel_used`, `peak_memory_bytes`, `net_requests`, `queued/setup/run/collect/total_ms`. Status = error (code) for `error`/`trap`. Requests rejected before running get no span (they are counted in `sandboxd.rejected`). | O1.2. **No** code, output, paths, URLs, error messages or principal. `run_id` correlates with the audit log, which holds the details. |
| Isolation | Export runs on the SDK's threads (batch span processor, periodic reader). Recording only enqueues, and full queues drop. Exporter timeout 10s. The reqwest *blocking* client is created and dropped on a plain OS thread (never a tokio worker). | O1.3: a failing collector never blocks or fails a run. |
| Shutdown | `Telemetry::shutdown()` flushes spans and a final metric collection, bounded at 10s. Called on exit by `serve`, `mcp` and one-shot `run`. | O1.3 |
| TLS | `Telemetry` installs the `ring` rustls provider itself (idempotent) | Found by the test: with `rustls-no-provider` (shared with the broker), a library user without the binary's `main` would panic on the first client. |
| Data | `RunResult.net_requests` (runtime) | The span's request count (FR-O1.2) |

## Files
| File | Change |
|---|---|
| `crates/sandboxd-server/src/otel.rs` (new) | `Telemetry` (`init`/`enabled`/`shutdown`/`compiled_in`); an inert handle without the feature. `Instruments` mirrors; `record_run_span`. |
| `crates/sandboxd-server/src/metrics.rs` | `record_run`, `queue_add`, `running_add`, `audit_healthy_set`, `reject`, `startup_ms_set` update Prometheus and OTel together |
| `crates/sandboxd-server/src/service.rs` | Uses those methods; records the span after each run |
| `crates/sandboxd-server/src/config.rs` | Endpoint validation; `otlp_interval` |
| `crates/sandboxd/src/main.rs` | `Telemetry::init` before `RunService::new`; flush on exit (serve / mcp / run) |
| `crates/sandboxd-runtime` | `RunResult.net_requests` |
| `Cargo.toml`s | Optional OTel deps (+ `rustls` for the provider) behind `otel` |
| `.github/workflows/ci.yml` | New `otel` job: the default build has no OpenTelemetry crates, plus clippy and tests with `--features otel` |
| `docs/MCP.md` | `[telemetry]` example |

## Tests (all pass)
| Test | Proves |
|---|---|
| `otlp_export_spans_and_metrics_and_failure_isolation` (in-process OTLP/HTTP collector stub) | Three runs (ok, exit 3, JS wall-clock limit) plus a rejected request. After `shutdown()` the stub received spans (`sandboxd.run`, language, outcome `ok`/`exit`/`limit`, `limits_hit` = `wall_clock`, fuel, net_requests, total_ms, exit_code, the real `run_id`, `service.name = sandboxd`) and metrics (`sandboxd.runs`, `sandboxd.run.duration`, `limits_hit`, `rejected` with `policy_not_found`, `queue_depth`, `running`). **No program text, output or principal appears in any exported byte.** Then, against a dead collector: 3 runs finish normally in < 5s, and shutdown completes in < 12s. |
| `no_endpoint_means_no_export` | No endpoint → disabled handle |
| `telemetry_endpoint_and_interval` (unit) | Valid config; empty = off; rejects a non-HTTP scheme, a missing scheme, an interval out of range, and unknown keys |
| `cargo tree` (manual + CI) | Default build: **0** opentelemetry/prost crates. `otel` build: a single reqwest 0.13.5 |

Workspace (default features): clippy `-D warnings`, fmt, all tests. With `--features otel`: clippy and server tests. cargo-deny (`all-features`) covers the new crates.

## Defect found and fixed during this unit (stdlib cache robustness)
After the C2-U3 network tests were moved onto the shared test cache, `bootstrap_is_invisible_to_programs` saw CPython path warnings ("Could not find platform dependent libraries…") before the traceback. That cache's extracted stdlib had lost the **empty** `lib/python3.15/lib-dynload` directory. CPython's `getpath` needs it, and the completion marker doesn't cover empty directories, so the cache was never repaired. How it disappeared is unknown (no code removes directories). **Fix:** `ensure_stdlib` re-creates `lib-dynload` on every start (idempotent). The stdlib unit test now deletes it and checks that it is restored. The C2-U3 byte-for-byte traceback test is what caught this.

## CI maintenance (user request during this unit): Node 24
GitHub is retiring Node 20 for JavaScript actions. Both workflows now set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` and use Node 24 releases:
- `actions/cache@v5`
- `actions/upload-artifact@v6`
- `actions/download-artifact@v7`
- `checkout@v5`, `setup-python@v6`, and `Swatinem/rust-cache@v2` (v2.9+) were already on Node 24.
- `rustsec/audit-check@v2` has no Node 24 release, so it is replaced by `cargo install cargo-audit --locked && cargo audit`, which needs no Node.
- `EmbarkStudios/cargo-deny-action` is Docker-based and unaffected.
