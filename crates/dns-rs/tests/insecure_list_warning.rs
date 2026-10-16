//! Plain-HTTP blocklists are flagged in the logs.
//!
//! Alone in its own test binary: tracing caches per-callsite interest
//! globally, so tests running in parallel could make this one miss events.

mod common;

use common::Capture;
use dns_rs::config::ListSource;
use dns_rs::sources::{Limits, ListLoader};
use tokio::net::TcpListener;

#[tokio::test]
async fn plain_http_list_logs_a_warning_and_https_does_not() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("dns_rs::sources=warn")
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Nothing needs to answer: the warning comes before the download.
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let loader = ListLoader::new(Limits::default()).unwrap();

    loader
        .load(&[
            ListSource::Http(format!("http://{closed}/plain")).into(),
            ListSource::Http(format!("https://{closed}/secure")).into(),
        ])
        .await;

    let logs = capture.text();
    let warnings: Vec<&str> = logs.lines().filter(|l| l.contains("plain HTTP")).collect();
    assert_eq!(warnings.len(), 1, "{logs}");
    assert!(warnings[0].contains("/plain"), "{logs}");
}
