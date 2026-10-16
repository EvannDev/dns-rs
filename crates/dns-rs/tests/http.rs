//! The HTTP endpoint: Kubernetes probes and Prometheus metrics.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{query, start_server, udp_exchange};
use dns_rs::http::{HttpState, serve_http};
use dns_rs::metrics::Metrics;
use tokio::net::TcpListener;

async fn start_http(metrics: Arc<Metrics>) -> (SocketAddr, HttpState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = HttpState::new(metrics);
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
