//! MCP server: `run_code`, `list_policies` and sessions (U5 design §3; C3-U4).

use std::time::Instant;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rmcp::{
    ErrorData, Peer, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, EmbeddedResource, Extensions, Implementation,
        ProgressNotificationParam, ProgressToken, RequestMetaObject, ResourceContents,
        ServerCapabilities, ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use sandboxd_runtime::{Language, RunEvent, RunResult, SessionEnd};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::{
    api::{ApiLanguage, ApiRunRequest, ApiRunResult, ApiSessionCreate, ApiSessionRun},
    auth::Principal,
    service::{RunService, ServiceError},
};

/// Shown to the model when it connects.
pub const INSTRUCTIONS: &str = "sandboxd runs untrusted Python or JavaScript in an isolated WebAssembly sandbox. \
Use `run_code` for calculations, data processing, parsing and transforming text/JSON/CSV, and checking logic. \
The sandbox has NO network access, NO package installation (pip/npm), and NO native extensions: \
numpy, pandas, scipy and similar are unavailable, so use the Python standard library (csv, json, statistics, \
decimal, datetime, re, itertools, collections) or plain JavaScript. The operator may also provide some pure-Python \
packages; `list_policies` lists them. Pass data as `files` (readable under /in); \
write result files to /out (they are returned as artifacts). Each run is fresh: nothing persists between calls, \
unless you create a session with `session_create` (if the policy allows it) and pass its `session_id` to `run_code`: \
then variables, imports and files under /work carry over, like notebook cells. Close it with `session_close` when done. \
Limits (time, memory, output) come from the selected policy; see `list_policies`.";

/// The MCP service. One instance per session; all share the [`RunService`].
#[derive(Clone)]
pub struct SandboxMcp {
    service: ServiceSlot,
    transport: &'static str,
    #[allow(dead_code, reason = "read by the #[tool_handler] macro expansion")]
    tool_router: ToolRouter<Self>,
}

/// Start-up state shared with a deferred server: `None` while the sandbox is being built.
type StartupState = Option<Result<RunService, String>>;

/// The run service, or a handle that resolves when a deferred start-up finishes (C5-U1).
#[derive(Clone)]
enum ServiceSlot {
    Ready(RunService),
    Starting(tokio::sync::watch::Receiver<StartupState>),
}

/// Completes a deferred start-up created with [`SandboxMcp::deferred`]. Dropping it without
/// calling [`ready`](Self::ready) fails every waiting and future tool call.
#[derive(Debug)]
pub struct StartupHandle(tokio::sync::watch::Sender<StartupState>);

impl StartupHandle {
    /// The sandbox is built: waiting tool calls proceed.
    pub fn ready(self, service: RunService) {
        self.0.send_replace(Some(Ok(service)));
    }

    /// Start-up failed: tool calls return `STARTUP_FAILED` with this reason.
    pub fn failed(self, reason: impl Into<String>) {
        self.0.send_replace(Some(Err(reason.into())));
    }
}

/// Shown (as progress) to a client whose tool call waits for a deferred start-up.
const STARTING_MESSAGE: &str =
    "sandboxd is starting (building the interpreter cache); the call runs when it is ready";

impl std::fmt::Debug for SandboxMcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxMcp")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

#[tool_router]
impl SandboxMcp {
    /// `transport` labels the principal for unauthenticated local use (e.g. `mcp-stdio`).
    pub fn new(service: RunService, transport: &'static str) -> Self {
        Self {
            service: ServiceSlot::Ready(service),
            transport,
            tool_router: Self::tool_router(),
        }
    }

    /// A server that answers the protocol (`initialize`, `tools/list`) at once while the sandbox
    /// is still being built; tool calls wait for the [`StartupHandle`] (C5-U1, FR-ST1).
    pub fn deferred(transport: &'static str) -> (Self, StartupHandle) {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let server = Self {
            service: ServiceSlot::Starting(rx),
            transport,
            tool_router: Self::tool_router(),
        };
        (server, StartupHandle(tx))
    }

    /// The run service, waiting for a deferred start-up. With a progress token, a call that has
    /// to wait first tells the client why.
    async fn ready(
        &self,
        progress: Option<(&Peer<RoleServer>, &ProgressToken)>,
    ) -> Result<RunService, CallToolResult> {
        let rx = match &self.service {
            ServiceSlot::Ready(s) => return Ok(s.clone()),
            ServiceSlot::Starting(rx) => rx,
        };
        let starting = rx.borrow().is_none();
        if starting && let Some((peer, token)) = progress {
            let _ = peer
                .notify_progress(
                    ProgressNotificationParam::new(token.clone(), 0.0)
                        .with_message(STARTING_MESSAGE),
                )
                .await;
        }
        let mut rx = rx.clone();
        let state = rx.wait_for(Option::is_some).await.map(|s| s.clone());
        match state {
            Ok(Some(Ok(service))) => Ok(service),
            Ok(Some(Err(reason))) => Err(startup_failed(&reason)),
            Ok(None) | Err(_) => Err(startup_failed("sandboxd stopped during start-up")),
        }
    }

    #[tool(
        name = "run_code",
        description = "Run a Python 3.15 or JavaScript (QuickJS, ES module) program in an isolated sandbox and return its stdout, stderr, exit status and any files it wrote to /out. No network, no pip/npm, standard library only (no numpy/pandas). Input files go in `files` and appear read-only under /in. Print results to stdout or write them to /out."
    )]
    async fn run_code(
        &self,
        Parameters(req): Parameters<ApiRunRequest>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
        extensions: Extensions,
    ) -> Result<CallToolResult, ErrorData> {
        let principal = self.principal(&extensions);
        let token = meta.get_progress_token();
        let service = match self.ready(token.as_ref().map(|t| (&peer, t))).await {
            Ok(s) => s,
            Err(failed) => return Ok(failed),
        };

        // Stream output as progress notifications when the client asked for progress.
        let (events, forward) = match token {
            Some(token) => {
                let (tx, mut rx) = mpsc::channel::<RunEvent>(64);
                let t0 = Instant::now();
                let task = tokio::spawn(async move {
                    let mut step = 0.0_f64;
                    while let Some(ev) = rx.recv().await {
                        let msg = match ev {
                            RunEvent::Stdout(b) => String::from_utf8_lossy(&b).into_owned(),
                            RunEvent::Stderr(b) => {
                                format!("[stderr] {}", String::from_utf8_lossy(&b))
                            }
                            RunEvent::LimitHit(k) => format!("[limit] {k:?}"),
                            RunEvent::Finished(_) => break,
                        };
                        step = step.max(t0.elapsed().as_secs_f64() * 1000.0) + 1.0;
                        let _ = peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), step)
                                    .with_message(msg),
                            )
                            .await;
                    }
                });
                (Some(tx), Some(task))
            }
            None => (None, None),
        };

        let outcome = match req.into_session_call_or_run() {
            Ok(req) => service
                .submit(&principal, req, events)
                .await
                .map(|r| (r, None)),
            Err((id, language, policy, call)) => {
                Self::session_call(&service, &principal, &id, language, policy, call, events)
                    .await
                    .map(|(r, ended)| (r, Some((id, ended))))
            }
        };
        if let Some(t) = forward {
            let _ = t.await;
        }
        Ok(match outcome {
            Ok((r, session)) => tool_result(&r, session),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{}: {e}", e.code()))]),
        })
    }

    async fn session_call(
        service: &RunService,
        principal: &Principal,
        id: &str,
        language: ApiLanguage,
        policy: Option<String>,
        call: ApiSessionRun,
        events: Option<mpsc::Sender<RunEvent>>,
    ) -> Result<(RunResult, Option<SessionEnd>), ServiceError> {
        let info = service.session_info(principal, id)?;
        if Language::from(language).as_str() != info.language {
            return Err(ServiceError::InvalidRequest(format!(
                "session {id} runs {}, not {}",
                info.language,
                Language::from(language).as_str()
            )));
        }
        if let Some(p) = policy.filter(|p| !p.is_empty() && *p != info.policy) {
            return Err(ServiceError::InvalidRequest(format!(
                "session {id} uses policy {:?}, not {p:?}",
                info.policy
            )));
        }
        service.session_run(principal, id, call, events).await
    }

    #[tool(
        name = "session_create",
        description = "Start a persistent sandbox session (like a notebook kernel) for Python or JavaScript. Pass the returned session_id to run_code: variables, functions, imports and files under /work persist between calls; stdout, /out and the time limit are per call. The policy must enable sessions. Sessions end after idle_timeout_s without a call, at expires_at, on a time/CPU limit, or with session_close."
    )]
    async fn session_create(
        &self,
        Parameters(req): Parameters<ApiSessionCreate>,
        extensions: Extensions,
    ) -> Result<CallToolResult, ErrorData> {
        let principal = self.principal(&extensions);
        let service = match self.ready(None).await {
            Ok(s) => s,
            Err(failed) => return Ok(failed),
        };
        Ok(match service.create_session(&principal, req).await {
            Ok(s) => {
                let text = format!(
                    "session {} created ({}, policy {}). Pass session_id to run_code. Ends after {} s idle, at {} at the latest, or after {} calls.",
                    s.session_id, s.language, s.policy, s.idle_timeout_s, s.expires_at, s.max_calls
                );
                let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
                r.structured_content = serde_json::to_value(&s).ok();
                r
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{}: {e}", e.code()))]),
        })
    }

    #[tool(
        name = "session_close",
        description = "End a session created with session_create and free its resources."
    )]
    async fn session_close(
        &self,
        Parameters(req): Parameters<SessionRef>,
        extensions: Extensions,
    ) -> Result<CallToolResult, ErrorData> {
        let principal = self.principal(&extensions);
        let service = match self.ready(None).await {
            Ok(s) => s,
            Err(failed) => return Ok(failed),
        };
        Ok(
            match service.close_session(&principal, &req.session_id).await {
                Ok(s) => {
                    let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
                        "session {} closed after {} calls",
                        s.session_id, s.calls
                    ))]);
                    r.structured_content = serde_json::to_value(&s).ok();
                    r
                }
                Err(e) => {
                    CallToolResult::error(vec![ContentBlock::text(format!("{}: {e}", e.code()))])
                }
            },
        )
    }

    fn principal(&self, extensions: &Extensions) -> Principal {
        extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<Principal>().cloned())
            .unwrap_or_else(|| Principal::local(self.transport))
    }

    #[tool(
        name = "list_policies",
        description = "List the sandbox policies you can pass as `policy` to run_code, with their time and memory limits and any read-only data mounts."
    )]
    async fn list_policies(&self) -> Result<CallToolResult, ErrorData> {
        let (ps, packages) = match self.ready(None).await {
            Ok(s) => (s.policies(), s.packages()),
            Err(failed) => return Ok(failed),
        };
        let text = ps
            .iter()
            .map(|p| {
                let mounts = if p.mounts.is_empty() {
                    String::new()
                } else {
                    format!("; mounts: {}", p.mounts.join(", "))
                };
                format!(
                    "- {}: {} (wall clock {}, memory {}{mounts})",
                    p.name, p.description, p.wall_clock, p.memory
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let text = if packages.is_empty() {
            text
        } else {
            format!(
                "{text}\n\nPython packages available (pure Python, import them directly; policies may opt out): {}",
                packages.join(", ")
            )
        };
        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content =
            serde_json::to_value(serde_json::json!({ "policies": ps, "packages": packages })).ok();
        Ok(r)
    }
}

/// The tool result for calls made after a failed deferred start-up (FR-ST1.3).
fn startup_failed(reason: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "STARTUP_FAILED: sandboxd could not start: {reason}"
    ))])
}

/// `session_close` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    /// The id returned by session_create.
    pub session_id: String,
}

/// Build the MCP tool result (Q2: artifacts as embedded resources).
fn tool_result(r: &RunResult, session: Option<(String, Option<SessionEnd>)>) -> CallToolResult {
    let mut api = ApiRunResult::from(r);
    let mut summary = format!("outcome: {}", api.outcome);
    if let Some(c) = api.exit_code {
        summary.push_str(&format!(", exit code {c}"));
    }
    if !api.limits_hit.is_empty() {
        summary.push_str(&format!(", limits hit: {}", api.limits_hit.join(", ")));
    }
    if let Some(e) = &api.error {
        summary.push_str(&format!("\nerror {}: {}", e.code, e.message));
    }
    summary.push_str(&format!(
        "\nduration: {} ms, run id {}",
        api.timings.total_ms, api.run_id
    ));
    if let Some((id, ended)) = session {
        if let Some(reason) = ended {
            summary.push_str(&format!(
                "\nsession {id} has ended ({reason}); create a new one to continue"
            ));
        }
        api.session_id = Some(id);
        api.session_ended = ended.map(|e| e.as_str().to_string());
    }
    let mut content = vec![ContentBlock::text(summary)];
    if !api.stdout.is_empty() {
        let t = if api.stdout_truncated {
            " (truncated)"
        } else {
            ""
        };
        content.push(ContentBlock::text(format!("stdout{t}:\n{}", api.stdout)));
    }
    if !api.stderr.is_empty() {
        let t = if api.stderr_truncated {
            " (truncated)"
        } else {
            ""
        };
        content.push(ContentBlock::text(format!("stderr{t}:\n{}", api.stderr)));
    }
    if !r.artifacts.is_empty() {
        let list = r
            .artifacts
            .iter()
            .map(|a| format!("- /out/{} ({} bytes)", a.name, a.bytes.len()))
            .collect::<Vec<_>>()
            .join("\n");
        content.push(ContentBlock::text(format!("artifacts:\n{list}")));
        for a in &r.artifacts {
            let uri = format!("sandboxd://runs/{}/out/{}", r.run_id, a.name);
            let res = match std::str::from_utf8(&a.bytes) {
                Ok(text) => {
                    ResourceContents::text(text, uri).with_mime_type(guess_mime(&a.name, true))
                }
                Err(_) => ResourceContents::blob(B64.encode(&a.bytes), uri)
                    .with_mime_type(guess_mime(&a.name, false)),
            };
            content.push(ContentBlock::Resource(EmbeddedResource::new(res)));
        }
    }
    let failed = matches!(api.outcome.as_str(), "trap" | "error");
    let mut structured = api;
    for a in &mut structured.artifacts {
        a.content_base64.clear(); // content is in the embedded resources; don't send it twice
    }
    let mut out = if failed {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    out.structured_content = serde_json::to_value(&structured).ok();
    out
}

fn guess_mime(name: &str, text: bool) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "json" => "application/json",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "html" | "htm" => "text/html",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ if text => "text/plain",
        _ => "application/octet-stream",
    }
}

#[tool_handler]
impl ServerHandler for SandboxMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("sandboxd", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
