//! HTTP endpoint: Kubernetes probes and Prometheus metrics.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;

use crate::blocking::BlockingMode;
use arc_swap::ArcSwap;

use crate::config::ApiToken;
use crate::filter::{Match, Verdict};
use crate::handler::PolicyView;
use crate::metrics::Metrics;
use crate::status::{Status, StatusReport};

/// What the endpoint serves, shared with the rest of dns-rs.
#[derive(Clone)]
pub struct HttpState {
    metrics: Arc<Metrics>,
    policy: Arc<dyn PolicyView>,
    status: Arc<Status>,
    api_token: ApiTokenSlot,
    ready: Arc<AtomicBool>,
}

/// The API token in force, swapped by the Reloader when its file changes.
pub type ApiTokenSlot = Arc<ArcSwap<Option<ApiToken>>>;

impl HttpState {
    /// `api_token`: the token `/api/*` requests must present, read at each
    /// request; without one, the API is disabled.
    #[must_use]
    pub fn new(
        metrics: Arc<Metrics>,
        policy: Arc<dyn PolicyView>,
        status: Arc<Status>,
        api_token: ApiTokenSlot,
    ) -> Self {
        Self {
            metrics,
            policy,
            status,
            api_token,
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
    // Probes and metrics stay open for the kubelet and Prometheus; the API,
    // which reveals the blocking policy, needs the token.
    // `layer` (not `route_layer`) with a fallback covers the whole prefix:
    // an endpoint added later cannot be left open, and unknown paths reveal
    // nothing without the token.
    let api = Router::new()
        .route("/v1/check/{domain}", get(check))
        .route("/v1/status", get(status))
        .fallback(api_not_found)
        .layer(middleware::from_fn_with_state(state.clone(), require_token));
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .nest("/api", api)
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

/// The state of this replica: policy, configuration, cache and lists.
async fn status(State(state): State<HttpState>) -> Json<StatusReport> {
    Json(state.status.report())
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
    // An empty name is one empty label, rejected below.
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

async fn api_not_found() -> Response {
    let error = "no such API endpoint".to_owned();
    (StatusCode::NOT_FOUND, Json(ErrorResponse { error })).into_response()
}

/// Lets a request through only if it carries `Authorization: Bearer <token>`
/// with the configured token; without a configured token, the API is off.
async fn require_token(State(state): State<HttpState>, request: Request, next: Next) -> Response {
    let token = state.api_token.load();
    let Some(token) = token.as_ref() else {
        let error = "the API is disabled: set DNS_RS_API_TOKEN or http.api_token_file".to_owned();
        return (StatusCode::FORBIDDEN, Json(ErrorResponse { error })).into_response();
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    match presented {
        Some(presented) if token.matches(presented) => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "missing or invalid API token".to_owned(),
            }),
        )
            .into_response(),
    }
}

/// The token of a `Bearer` authorization; the scheme is case-insensitive
/// (RFC 9110 section 11.1).
fn bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_names_within_dns_limits_are_accepted() {
        let label_63 = "a".repeat(63);
        // 4 labels of 63 + 3 dots = 255; trim to exactly 253 bytes.
        let name_253 = format!("{label_63}.{label_63}.{label_63}.{}", "a".repeat(61));
        assert_eq!(name_253.len(), 253);

        for name in [
            "example.com",
            "example.com.",
            "_dmarc.example.com",
            "localhost",
            &format!("{label_63}.com"),
            &name_253,
        ] {
            assert!(is_query_name(name), "{name}");
        }
    }

    #[test]
    fn query_names_beyond_dns_limits_are_rejected() {
        let label_64 = "a".repeat(64);
        let name_254 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(62)
        );
        assert_eq!(name_254.len(), 254);

        for name in [
            "",
            ".",
            "..",
            "a..b",
            ".example.com",
            "exa mple.com",
            "ex%41mple.com",
            &format!("{label_64}.com"),
            &name_254,
        ] {
            assert!(!is_query_name(name), "{name:?}");
        }
    }
}
