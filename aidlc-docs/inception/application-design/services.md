# Services & Orchestration — sandboxd

## RunService (C5): the only orchestrator
The CLI, HTTP and MCP all call `RunService::submit(principal, RunRequest) -> impl Stream<RunEvent>`. No interface talks to `Sandbox` directly, so auth, admission and audit can't be bypassed.

### Request lifecycle
```mermaid
sequenceDiagram
    participant A as Agent (CLI/HTTP/MCP)
    participant S as RunService
    participant P as PolicyStore
    participant X as Sandbox (runtime)
    participant V as RunFs + FsInterposer
    participant L as AuditSink
    A->>S: run_code(lang, code, policy, files)
    S->>S: authN (bearer) · validate sizes
    S->>P: get(policy) → Arc<Policy>  (unknown ⇒ PolicyNotFound)
    S->>S: admission: semaphore.acquire (bounded queue, timeout ⇒ Overloaded/429)
    S->>X: execute(req, policy, events)
    X->>L: RunStart
    X->>X: NativeExtGuard pre-scan
    X->>V: RunFs::create (inputs ro, /out rw, mounts, stdlib ro)
    X->>X: pool.acquire → InstancePre; Store{fuel, epoch deadline, limiter}
    loop guest executes
        X-->>A: Stdout/Stderr chunks (stream)
        V->>L: FsOpen allow/deny
    end
    X->>X: trap? classify → limits_hit / exit code
    X->>V: collect_artifacts (caps, sha256)
    X->>L: RunEnd
    X-->>A: Exit(RunResult)
    X->>V: drop RunFs (temp root deleted)
```

### Concurrency model (Q4=A)
- A tokio multi-thread runtime runs wasmtime with `async_support(true)`.
- **Wall clock:** a ticker task calls `engine.increment_epoch()` every 10 ms. Each store sets `epoch_deadline_async_yield_and_update(1)` so guests yield cooperatively, and a per-run deadline (`started + wall_clock`) triggers a trap. That gives timeout precision of about 10–20 ms.
- **CPU:** `store.set_fuel(policy.cpu_fuel)`. Running out of fuel causes a trap, classified as `cpu`.
- **Memory:** a `ResourceLimiterAsync` denies `memory.grow` past the cap. The guest sees a MemoryError or OOM, and the host records the `memory` limit hit.
- **Output:** stdout and stderr are custom `OutputStream`s with byte caps. On overflow the stream truncates, records the limit hit and traps the guest.
- **Admission:** a `Semaphore(max_concurrent)` plus a queue bound and a queue timeout (both in config).

### Error-classification rules (detailed in Functional Design)
| Signal | Result |
|---|---|
| `Trap::OutOfFuel` | `limits_hit=[cpu]`, exit_code=None |
| Epoch deadline passed | `limits_hit=[wall_clock]` |
| Limiter denied grow | `limits_hit=[memory]` (even if the guest exits normally after its MemoryError) |
| `proc_exit(n)` | exit_code=n |
| Other trap | `Trap(msg)`, with a sanitized message |

## Startup service (C6)
Load config → load and validate all policies (fail fast) → provision the cache (stdlib extract, module AOT compile, both hash-verified) → start the epoch ticker → start the selected front end (CLI one-shot, `serve`, or `mcp` stdio).
