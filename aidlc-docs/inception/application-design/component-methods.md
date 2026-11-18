# Component Methods & Key Types — sandboxd

Signatures are indicative. Detailed business rules come in Functional Design per unit.

## C1 Policy
```rust
pub struct Policy {                     // immutable, validated, schema v1
    pub name: PolicyName,
    pub limits: Limits,                 // cpu_fuel, wall_clock, memory_bytes, stdout_bytes, stderr_bytes,
                                        // artifact_count, artifact_bytes
    pub filesystem: Vec<Mount>,         // { guest_path, source: HostDir|Inputs, mode: Ro|Rw }
    pub env: BTreeMap<String, String>,  // explicit allowlist with literal values only
    pub network: NetworkPolicy,         // Phase 4: http rules, tcp rules, quotas (validated, unenforced)
    pub session: SessionPolicy,         // Phase 5: enabled, idle_ttl (validated, unenforced)
    pub audit: AuditPolicy,             // log_code, …
}
pub trait PolicyStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Arc<Policy>, PolicyError>;   // unknown → error, never fallback
    fn list(&self) -> Vec<PolicySummary>;
}
impl Policy {
    pub fn from_toml(src: &str) -> Result<Self, PolicyError>;
    pub fn from_yaml(src: &str) -> Result<Self, PolicyError>;
    pub fn tighten(&self, o: &Overrides) -> Result<Policy, PolicyError>; // rejects widening
    pub fn explain(&self) -> String;                                      // `policy check`
}
```

## C2 Audit
```rust
pub enum AuditEvent {
    RunStart { run_id, policy, lang, code_sha256, principal },
    RunEnd   { run_id, exit, duration, fuel_used, peak_mem, limits_hit },
    FsOpen   { run_id, guest_path, mode, decision: Allow|Deny(reason) },
    EnvRead  { run_id, key, decision },
    LimitHit { run_id, kind: Cpu|WallClock|Memory|Stdout|Stderr|Artifacts },
    PolicyDenied { run_id, what },
    NetRequest { .. }                     // Phase 4 (variant reserved)
}
pub trait AuditSink: Send + Sync { fn emit(&self, ev: AuditEvent); }  // non-blocking
```

## C3 VFS
```rust
pub struct RunFs { /* temp root, mount table, caps */ }
impl RunFs {
    pub fn create(policy: &Policy, inputs: Vec<InputFile>, cache: &Cache) -> Result<Self, VfsError>;
    pub fn wasi_preopens(&self) -> Vec<Preopen>;               // fed to WasiCtxBuilder
    pub fn collect_artifacts(&self) -> Result<Vec<Artifact>, VfsError>;
}
pub trait FsInterposer: Send + Sync {
    fn check_path(&self, ctx: &FdContext, rel: &str, op: FsOp) -> Decision;  // canonicalize + rules
    fn on_opened(&mut self, parent: Fd, rel: &str, new_fd: Fd);               // fd → virtual path map
}
pub trait VirtualDevice: Send {                                  // ADR-002; network devices in Phase 4
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno>;
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Errno>;
    async fn close(&mut self) -> Result<(), Errno>;
}
```

## C4 Runtime
```rust
pub trait Interpreter: Send + Sync {
    fn language(&self) -> Language;                 // Python | JavaScript
    fn module(&self) -> &InstancePre<HostState>;
    fn prepare(&self, code: &str, fs: &mut RunFs) -> Result<GuestArgs, RunError>;
}
pub struct Sandbox { engine: Engine, interpreters: Interpreters, pool: Arc<dyn InstancePool>, audit: Arc<dyn AuditSink> }
impl Sandbox {
    pub async fn execute(&self, req: RunRequest, policy: Arc<Policy>, events: EventTx) -> RunResult;
}
pub trait InstancePool: Send + Sync {            // naive impl this cycle; snapshot pool in Phase 5
    async fn acquire(&self, lang: Language) -> Result<Prepared, RunError>;
}
pub trait FallbackBackend: Send + Sync {         // no impl this cycle
    async fn execute(&self, req: RunRequest, policy: Arc<Policy>) -> RunResult;
}
pub trait SessionStore: Send + Sync { /* reserved: create, resume, evict */ }
pub trait NetworkBroker: Send + Sync {           // Phase 4
    async fn http(&self, run: &RunCtx, req: HttpRequest) -> Result<HttpResponse, NetDenied>;
    async fn tcp_connect(&self, run: &RunCtx, host: &str, port: u16) -> Result<Box<dyn VirtualDevice>, NetDenied>;
}
```

## Shared types
```rust
pub struct RunRequest { pub language: Language, pub code: String, pub policy: String,
                        pub files: Vec<InputFile>, pub args: Vec<String>, pub stdin: Option<Vec<u8>>,
                        pub overrides: Overrides /* CLI only */, pub session: Option<SessionId> }
pub struct RunResult  { pub run_id: RunId, pub exit_code: Option<i32>, pub stdout: Bytes, pub stderr: Bytes,
                        pub artifacts: Vec<Artifact>, pub limits_hit: Vec<LimitKind>,
                        pub error: Option<RunErrorCode>, pub timings: Timings }
pub enum RunEvent     { Stdout(Bytes), Stderr(Bytes), LimitHit(LimitKind), Exit(RunResult) }
pub enum RunErrorCode { UnsupportedNativeExtension{module}, PolicyNotFound, Rejected(Overloaded),
                        Trap(String), Internal }
```
