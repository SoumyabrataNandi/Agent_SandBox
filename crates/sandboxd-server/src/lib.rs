//! Front door for sandboxd (component C5, unit U5).
//!
//! `RunService` (admission control, streaming), axum HTTP + SSE, rmcp MCP server, bearer auth.
//! Implemented in U5.

#![forbid(unsafe_code)]
