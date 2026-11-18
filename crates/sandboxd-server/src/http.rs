//! HTTP API + MCP Streamable HTTP on one axum router (U5 design §2–§4).

use std::{convert::Infallible, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use futures::{StreamExt, stream};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use sandboxd_runtime::RunEvent;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    api::{ApiError, ApiRunRequest, ApiRunResult},
    auth::{Principal, TokenSet},
    mcp::SandboxMcp,
    service::{RunService, ServiceError},
};

/// Everything the router needs.
#[derive(Clone)]
pub struct AppState {
    pub service: RunService,
    pub tokens: Arc<TokenSet>,
    pub metrics_public: bool,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("metrics_public", &self.metrics_public)
            .finish_non_exhaustive()
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = Json(
            json!({ "error": ApiError { code: self.code().into(), message: self.to_string() } }),
        );
        let mut resp = (status, body).into_response();
        if matches!(self, ServiceError::Overloaded) {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        if matches!(self, ServiceError::Unauthorized) {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

/// Bearer auth. With no tokens configured (loopback-only by bind safety), requests are local.
async fn require_auth(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let principal = if st.tokens.is_empty() {
        Some(Principal::local("local-unauthenticated"))
    } else {
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(TokenSet::bearer)
            .and_then(|t| st.tokens.verify(t))
    };
    match principal {
        Some(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        None => ServiceError::Unauthorized.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RunQuery {
    #[serde(default)]
    stream: bool,
}

async fn run(
    State(st): State<AppState>,
    Query(q): Query<RunQuery>,
    axum::Extension(principal): axum::Extension<Principal>,
    body: Result<Json<ApiRunRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => {
            let status = e.status();
            let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
                "PAYLOAD_TOO_LARGE"
            } else {
                "INVALID_REQUEST"
            };
            return (
                status,
                Json(json!({ "error": { "code": code, "message": e.body_text() } })),
            )
                .into_response();
        }
    };
    if !q.stream {
        return match st.service.submit(&principal, req, None).await {
            Ok(r) => Json(ApiRunResult::from(&r)).into_response(),
            Err(e) => e.into_response(),
        };
    }
    // SSE: run in the background, stream events, finish with `result` (or `error`).
    let (tx, rx) = mpsc::channel::<RunEvent>(64);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(), ServiceError>>();
    let svc = st.service.clone();
    tokio::spawn(async move {
        let r = svc.submit(&principal, req, Some(tx)).await.map(|_| ());
        let _ = done_tx.send(r);
    });
    let events = tokio_stream_from(rx).map(|ev| -> Result<Event, Infallible> {
        Ok(match ev {
            RunEvent::Stdout(b) => Event::default()
                .event("stdout")
                .json_data(chunk(&b))
                .unwrap_or_default(),
            RunEvent::Stderr(b) => Event::default()
                .event("stderr")
                .json_data(chunk(&b))
                .unwrap_or_default(),
            RunEvent::LimitHit(k) => Event::default()
                .event("limit")
                .json_data(json!({ "kind": k }))
                .unwrap_or_default(),
            RunEvent::Finished(r) => Event::default()
                .event("result")
                .json_data(ApiRunResult::from(&*r))
                .unwrap_or_default(),
        })
    });
    // If the service refused before running, no events arrive; emit the error instead.
    let tail = stream::once(async move {
        match done_rx.await {
            Ok(Err(e)) => Some(Ok(Event::default()
                .event("error")
                .json_data(
                    json!({ "error": ApiError { code: e.code().into(), message: e.to_string() } }),
                )
                .unwrap_or_default())),
            _ => None,
        }
    })
    .filter_map(|x| async move { x });
    Sse::new(events.chain(tail))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn chunk(b: &[u8]) -> serde_json::Value {
    match std::str::from_utf8(b) {
        Ok(s) => json!({ "text": s }),
        Err(_) => json!({ "text": String::from_utf8_lossy(b), "base64": B64.encode(b) }),
    }
}

fn tokio_stream_from<T: Send + 'static>(
    mut rx: mpsc::Receiver<T>,
) -> impl futures::Stream<Item = T> {
    stream::poll_fn(move |cx| rx.poll_recv(cx))
}

async fn policies(State(st): State<AppState>) -> Response {
    Json(json!({ "policies": st.service.policies() })).into_response()
}

async fn healthz(State(st): State<AppState>) -> Response {
    if st.service.healthy() {
        Json(json!({ "status": "ok" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "audit_unavailable" })),
        )
            .into_response()
    }
}

async fn metrics(State(st): State<AppState>) -> Response {
    st.service.healthy(); // refresh the gauge
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        st.service.metrics().render(),
    )
        .into_response()
}

/// Build the full router: `/v1/*`, `/healthz`, `/metrics`, `/mcp`.
pub fn router(state: AppState, max_request_bytes: usize) -> Router {
    let auth = middleware::from_fn_with_state(state.clone(), require_auth);
    let mcp_service = {
        let svc = state.service.clone();
        StreamableHttpService::new(
            move || Ok(SandboxMcp::new(svc.clone(), "mcp-http")),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        )
    };
    let api = Router::new()
        .route("/v1/runs", post(run))
        .route("/v1/policies", get(policies))
        .nest_service("/mcp", mcp_service);
    let api = if state.metrics_public {
        api.layer(auth).route("/metrics", get(metrics))
    } else {
        api.route("/metrics", get(metrics)).layer(auth)
    };
    Router::new()
        .route("/healthz", get(healthz))
        .merge(api)
        .layer(RequestBodyLimitLayer::new(max_request_bytes))
        .with_state(state)
}
