//! HTTP endpoint: Kubernetes probes and Prometheus metrics.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;

use crate::metrics::Metrics;

/// What the endpoint serves, shared with the rest of dns-rs.
#[derive(Clone)]
pub struct HttpState {
    metrics: Arc<Metrics>,
    ready: Arc<AtomicBool>,
}

impl HttpState {
    #[must_use]
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
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
        .with_state(state);
    axum::serve(listener, router).await
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
