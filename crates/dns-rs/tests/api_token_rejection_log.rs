//! A broken API token file is logged once, not at every poll.
//!
//! Alone in its own test binary: tracing caches per-callsite interest
//! globally, so tests running in parallel could make this one miss events.

mod common;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use common::Capture;
use dns_rs::cache::DnsCache;
use dns_rs::config::Config;
use dns_rs::handler::Handler;
use dns_rs::http::ApiTokenSlot;
use dns_rs::metrics::Metrics;
use dns_rs::reload::Reloader;
use dns_rs::sources::{Limits, ListLoader};
use dns_rs::status::Status;
use dns_rs::upstream::DnsUpstream;

const VALID: &str = "valid-token-0123456789";
const ROTATED: &str = "rotated-token-0123456789";

#[tokio::test]
async fn broken_token_file_is_logged_once_until_it_is_fixed() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("dns_rs::reload=error")
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, VALID).unwrap();
    let path = token_file.display().to_string();
    let lookup = move |var: &str| (var == "DNS_RS_API_TOKEN_FILE").then(|| path.clone());
    let config = Config::load(&lookup).unwrap();
    let slot: ApiTokenSlot = Arc::new(ArcSwap::from_pointee(config.api_token(&lookup).unwrap()));
    // Never queried: the reloader only needs a handler to install policies.
    let upstream = DnsUpstream::new("127.0.0.1:9".parse().unwrap(), Duration::from_secs(1));
    let mut reloader = Reloader::start(
        Arc::new(Handler::new(upstream, DnsCache::new(10))),
        Arc::new(Metrics::new()),
        Arc::new(Status::new()),
        ListLoader::new(Limits::default()).unwrap(),
        config,
        lookup,
    )
    .await
    .unwrap()
    .with_api_token(slot);
    let rejections = || capture.text().matches("API token rejected").count();

    std::fs::write(&token_file, "short").unwrap();
    reloader.reload_api_token().await;
    reloader.reload_api_token().await;
    assert_eq!(rejections(), 1, "{}", capture.text());

    // Fixed, then broken again: a new incident, logged again.
    std::fs::write(&token_file, ROTATED).unwrap();
    reloader.reload_api_token().await;
    std::fs::write(&token_file, "short").unwrap();
    reloader.reload_api_token().await;
    assert_eq!(rejections(), 2, "{}", capture.text());
}
