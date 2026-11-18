//! MCP server: `run_code` and `list_policies` (U5 design §3).

use std::time::Instant;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rmcp::{
    ErrorData, Peer, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, EmbeddedResource, Extensions, Implementation,
        ProgressNotificationParam, RequestMetaObject, ResourceContents, ServerCapabilities,
        ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use sandboxd_runtime::{RunEvent, RunResult};
use tokio::sync::mpsc;

use crate::{
    api::{ApiRunRequest, ApiRunResult},
    auth::Principal,
    service::RunService,
};

/// Shown to the model when it connects.
pub const INSTRUCTIONS: &str = "sandboxd runs untrusted Python or JavaScript in an isolated WebAssembly sandbox. \
Use `run_code` for calculations, data processing, parsing and transforming text/JSON/CSV, and checking logic. \
The sandbox has NO network access, NO package installation (pip/npm), and NO native extensions: \
numpy, pandas, scipy and similar are unavailable, so use the Python standard library (csv, json, statistics, \
decimal, datetime, re, itertools, collections) or plain JavaScript. Pass data as `files` (readable under /in); \
write result files to /out (they are returned as artifacts). Each run is fresh: nothing persists between calls. \
Limits (time, memory, output) come from the selected policy; see `list_policies`.";

/// The MCP service. One instance per session; all share the [`RunService`].
#[derive(Clone)]
pub struct SandboxMcp {
    service: RunService,
    transport: &'static str,
    #[allow(dead_code, reason = "read by the #[tool_handler] macro expansion")]
    tool_router: ToolRouter<Self>,
}

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
            service,
            transport,
            tool_router: Self::tool_router(),
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
        let principal = extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<Principal>().cloned())
            .unwrap_or_else(|| Principal::local(self.transport));

        // Stream output as progress notifications when the client asked for progress.
        let (events, forward) = match meta.get_progress_token() {
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

        let outcome = self.service.submit(&principal, req, events).await;
        if let Some(t) = forward {
            let _ = t.await;
        }
        Ok(match outcome {
            Ok(r) => tool_result(&r),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{}: {e}", e.code()))]),
        })
    }

    #[tool(
        name = "list_policies",
        description = "List the sandbox policies you can pass as `policy` to run_code, with their time and memory limits and any read-only data mounts."
    )]
    async fn list_policies(&self) -> Result<CallToolResult, ErrorData> {
        let ps = self.service.policies();
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
        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content = serde_json::to_value(serde_json::json!({ "policies": ps })).ok();
        Ok(r)
    }
}

/// Build the MCP tool result (Q2: artifacts as embedded resources).
fn tool_result(r: &RunResult) -> CallToolResult {
    let api = ApiRunResult::from(r);
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
