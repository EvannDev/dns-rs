//! The HTTP endpoint: Kubernetes probes and Prometheus metrics.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{query, start_server, udp_exchange};
use std::time::Duration;

use dns_rs::cache::DnsCache;
use dns_rs::config::Config;
use dns_rs::handler::Handler;
use dns_rs::http::{HttpState, serve_http};
use dns_rs::metrics::Metrics;
use dns_rs::upstream::DnsUpstream;
use tokio::net::TcpListener;

/// A handler whose policy denies `*.tracker.net` and `ads.example.com`, and
/// allows `ok.tracker.net`; its upstream is never queried.
fn policy() -> Arc<Handler<DnsUpstream>> {
    let config = Config::from_toml(
        "[blocking]\nmode = 'nxdomain'\ndeny = ['ads.example.com', '*.tracker.net']\nallow = ['ok.tracker.net']",
    )
    .unwrap();
    let upstream = DnsUpstream::new("127.0.0.1:9".parse().unwrap(), Duration::from_millis(1));
    let handler = Arc::new(Handler::new(upstream, DnsCache::new(1)));
    handler.set_policy(config.blocking.policy([]).unwrap());
    handler
}

async fn start_http(metrics: Arc<Metrics>) -> (SocketAddr, HttpState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = HttpState::new(metrics, policy());
    tokio::spawn(serve_http(listener, state.clone()));
    (addr, state)
}

async fn get(addr: SocketAddr, path: &str) -> reqwest::Response {
    reqwest::get(format!("http://{addr}{path}")).await.unwrap()
}

#[tokio::test]
async fn liveness_probe_answers_ok() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    let response = get(addr, "/healthz").await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
}

// Kubernetes must not route DNS traffic before the sockets are bound and
// the first policy is in place.
#[tokio::test]
async fn readiness_probe_waits_until_ready() {
    let (addr, state) = start_http(Arc::new(Metrics::new())).await;

    let before = get(addr, "/readyz").await.status();
    state.set_ready();
    let after = get(addr, "/readyz").await.status();

    assert_eq!(before, 503);
    assert_eq!(after, 200);
}

#[tokio::test]
async fn metrics_are_served_as_openmetrics() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    let response = get(addr, "/metrics").await;

    assert_eq!(response.status(), 200);
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        content_type.starts_with("application/openmetrics-text"),
        "{content_type}"
    );
    assert!(response.text().await.unwrap().contains("dns_rs_build_info"));
}

#[tokio::test]
async fn unknown_path_is_not_found() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    assert_eq!(get(addr, "/admin").await.status(), 404);
}

#[tokio::test]
async fn answered_queries_show_up_in_metrics() {
    let server = start_server().await;
    let (addr, _state) = start_http(Arc::clone(&server.metrics)).await;

    udp_exchange(server.udp, &query(1, "example.com.").to_vec().unwrap()).await;
    udp_exchange(server.udp, &query(2, "example.com.").to_vec().unwrap()).await;

    let text = get(addr, "/metrics").await.text().await.unwrap();
    assert!(
        text.contains(r#"dns_rs_queries_total{source="upstream",rcode="NOERROR",type="A"} 1"#),
        "{text}"
    );
    assert!(
        text.contains(r#"dns_rs_queries_total{source="cache",rcode="NOERROR",type="A"} 1"#),
        "{text}"
    );
}

// Undecodable queries (scans, attacks) are exactly what operators want to see.
#[tokio::test]
async fn malformed_queries_show_up_in_metrics() {
    let server = start_server().await;
    let (addr, _state) = start_http(Arc::clone(&server.metrics)).await;
    // A valid header announcing one question, but no question follows.
    let header = [0x00, 0x2A, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    udp_exchange(server.udp, &header).await;

    let text = get(addr, "/metrics").await.text().await.unwrap();
    assert!(
        text.contains(r#"dns_rs_queries_total{source="rejected",rcode="FORMERR",type="none"} 1"#),
        "{text}"
    );
}

async fn check(addr: SocketAddr, domain: &str) -> (u16, serde_json::Value) {
    let response = get(addr, &format!("/api/v1/check/{domain}")).await;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn check_explains_a_blocked_domain() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    let (status, body) = check(addr, "ads.example.com").await;

    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "domain": "ads.example.com",
            "blocked": true,
            "mode": "nxdomain",
            "denied_by": {"kind": "exact", "rule": "ads.example.com", "origin": "config:deny"},
            "allowed_by": null,
        })
    );
}

#[tokio::test]
async fn check_explains_an_exception() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    let (_, body) = check(addr, "ok.tracker.net").await;

    assert_eq!(body["blocked"], false);
    assert_eq!(body["denied_by"]["rule"], "*.tracker.net");
    assert_eq!(body["allowed_by"]["origin"], "config:allow");
}

#[tokio::test]
async fn check_of_an_unlisted_domain_names_no_rule() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;

    let (_, body) = check(addr, "example.com").await;

    assert_eq!(body["blocked"], false);
    assert_eq!(body["denied_by"], serde_json::Value::Null);
    assert_eq!(body["allowed_by"], serde_json::Value::Null);
}

#[tokio::test]
async fn check_of_an_invalid_name_is_a_bad_request() {
    let (addr, _state) = start_http(Arc::new(Metrics::new())).await;
    let too_long = format!("{}.com", "a".repeat(260));

    for name in ["exa%20mple.com", "a..b", too_long.as_str()] {
        let (status, body) = check(addr, name).await;

        assert_eq!(status, 400, "{name}");
        assert!(body["error"].is_string(), "{name}: {body}");
    }
}
