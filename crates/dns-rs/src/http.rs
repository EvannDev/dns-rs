//! HTTP endpoint: Kubernetes probes and Prometheus metrics.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::blocking::BlockingMode;
use crate::filter::{Explanation, Match, Verdict};
use crate::metrics::Metrics;

/// Read access to the blocking policy in force, for `/api/v1/check`.
pub trait PolicyView: Send + Sync {
    fn explain(&self, domain: &str) -> (BlockingMode, Explanation);
}

/// What the endpoint serves, shared with the rest of dns-rs.
#[derive(Clone)]
pub struct HttpState {
    metrics: Arc<Metrics>,
    policy: Arc<dyn PolicyView>,
    ready: Arc<AtomicBool>,
}

impl HttpState {
    #[must_use]
    pub fn new(metrics: Arc<Metrics>, policy: Arc<dyn PolicyView>) -> Self {
        Self {
            metrics,
            policy,
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Marks dns-rs ready to answer queries: `/readyz` then returns 200.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

/// Serves `/healthz`, `/readyz` and `/metrics` until the listener fails.
pub async fn serve_http(listener: TcpListener, state: HttpState) -> io::Result<()> {
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .route("/api/v1/check/{domain}", get(check))
        .with_state(state);
    axum::serve(listener, router).await
}

/// The answer of `/api/v1/check/{domain}`.
#[derive(Serialize)]
struct CheckResponse {
    domain: String,
    blocked: bool,
    mode: BlockingMode,
    denied_by: Option<Match>,
    allowed_by: Option<Match>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Whether `domain` is blocked by the policy in force, and by which rule.
async fn check(State(state): State<HttpState>, Path(domain): Path<String>) -> Response {
    if !is_query_name(&domain) {
        let error = format!("{domain:?} is not a domain name");
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error })).into_response();
    }
    let (mode, explanation) = state.policy.explain(&domain);
    Json(CheckResponse {
        domain,
        blocked: explanation.verdict == Verdict::Blocked,
        mode,
        denied_by: explanation.denied_by,
        allowed_by: explanation.allowed_by,
    })
    .into_response()
}

/// A name a client could query: DNS characters, labels of 1 to 63 bytes, at
/// most 253 bytes, an optional trailing dot.
fn is_query_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

async fn readiness(State(state): State<HttpState>) -> (StatusCode, &'static str) {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    }
}

async fn metrics(State(state): State<HttpState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        state.metrics.encode(),
    )
}
