//! Query logging, end to end.
//!
//! Kept in its own test binary, alone: tracing caches per-callsite interest
//! globally, so tests running in parallel without a subscriber could make
//! this one miss events.

mod common;

use common::{Capture, query, start_server, udp_exchange};

// The test runtime is single-threaded, so the thread-local subscriber also
// sees events from the server tasks it spawns.
#[tokio::test]
async fn logs_each_answered_query() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("dns_rs::query=info")
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let server = start_server().await;

    udp_exchange(server.udp, &query(7, "example.com.").to_vec().unwrap()).await;
    udp_exchange(server.udp, &query(8, "example.com.").to_vec().unwrap()).await;

    let logs = capture.text();
    let lines: Vec<&str> = logs.lines().collect();
    assert_eq!(lines.len(), 2, "{logs}");
    assert!(lines[0].contains("client=127.0.0.1"), "{logs}");
    assert!(lines[0].contains("name=example.com."), "{logs}");
    assert!(lines[0].contains("source=upstream"), "{logs}");
    assert!(lines[1].contains("source=cache"), "{logs}");
}
