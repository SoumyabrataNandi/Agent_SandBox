//! Front door for sandboxd (component C5, unit U5).
//!
//! * [`RunService`]: the only path to the sandbox (fail-closed audit check, policy lookup,
//!   admission control, metrics).
//! * [`http::router`]: `POST /v1/runs` (JSON or SSE), `GET /v1/policies`, `/healthz`, `/metrics`
//!   and MCP Streamable HTTP at `/mcp`, behind bearer auth.
//! * [`SandboxMcp`]: the MCP server (`run_code`, `list_policies`) for stdio and HTTP.
//!
//! Design: `aidlc-docs/construction/u5-server/design.md`.

#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod config;
pub mod http;
pub mod mcp;
mod metrics;
pub mod otel;
pub mod service;
mod sessions;

pub use auth::{Principal, TokenSet, generate_token, hash_token};
pub use config::{AuditDest, NetworkConfig, ServerConfig};
pub use mcp::{INSTRUCTIONS, SandboxMcp, StartupHandle};
pub use metrics::Metrics;
pub use otel::Telemetry;
pub use service::{AdmissionConfig, RunService, ServiceError};
