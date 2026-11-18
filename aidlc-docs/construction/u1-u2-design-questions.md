# U1 Policy + U2 Audit — Design Questions

Designs: `u1-policy/design.md`, `u2-audit/design.md`. Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — YAML parser crate
`serde_yaml` is deprecated (2024), and `serde_yml` has a troubled history. Current options:
A) `serde-saphyr` 2.2: actively maintained (released 2026-11-18), pure Rust, built-in budgets for alias/anchor/depth (billion-laughs protection), duplicate-key errors **(Recommended)**
B) `serde_norway` 0.9 (maintained fork of serde_yaml on unsafe-libyaml; last release 2024-12)
C) `serde_yaml_ng` 0.10 (fork, last release 2024-05)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Byte-size unit semantics
A) **All binary.** `128mb` = `128MiB` = 128×1024². Forgiving for operators, matches how memory is thought about, and the requirement example says `--memory 128mb` **(Recommended)**
B) **Strict SI.** `MB` = 10⁶ and `MiB` = 2²⁰
C) Accept only `KiB/MiB/GiB` and reject `mb`, to avoid any ambiguity
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — `[network]` / `[session]` sections before Phases 4/5 exist
A) Parse and validate them, but **refuse to load** a policy that *grants* anything (non-empty `http`/`tcp`, `session.enabled = true`), with an error like "requires network broker (not in this version)". This prevents a silent permission change on a future upgrade. `policy check` still validates them **(Recommended)**
B) Accept them with a warning; they're ignored until implemented
C) Reject the sections entirely (unknown key)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — Where does OpenTelemetry (FR-6.2) live?
A) **Move it to U5.** U2 ships the audit trail (JSONL). U5 adds metrics and traces (Prometheus `/metrics` + optional OTLP) where the run durations and queue depth actually live. Keeps the audit crate small and free of tokio **(Recommended)**
B) Keep it in U2 as an `OtelSink` exporting audit events as OTel logs
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — Audit durability
A) Flush after each drained batch. If the OS crashes, the last few ms of events can be lost; a process crash loses nothing that was flushed **(Recommended)**
B) Configurable `audit.fsync = "batch" | "never"` (`fsync` per batch for regulated deployments), default A
C) fsync every event (slow)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — If the audit log can't be written (disk full / permissions)
A) **Fail closed.** New runs are rejected with `AUDIT_UNAVAILABLE` until writes succeed again, and runs already in progress finish. This is what a security team will expect from "every run is audited" **(Recommended)**
B) Fail open: keep running, count dropped events, warn on stderr
C) Configurable, default fail-closed
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 7 — Audit log rotation
A) None built in. Rely on external rotation (logrotate `copytruncate`, or ship stdout to the platform's log system) and document it **(Recommended for v1)**
B) Built-in size-based rotation (`max_size`, `keep`)
C) Other (please describe after [Answer]: tag below)

[Answer]: 
