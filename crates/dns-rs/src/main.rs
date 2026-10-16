use std::sync::Arc;

use anyhow::Context;
use dns_rs::cache::DnsCache;
use dns_rs::config::Config;
use dns_rs::handler::Handler;
use dns_rs::reload::{CONFIG_POLL_INTERVAL, Reloader};
use dns_rs::server::{serve_tcp, serve_udp};
use dns_rs::sources::{Limits, ListLoader};
use dns_rs::upstream::DnsUpstream;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let upstream = DnsUpstream::new(config.upstream.server, config.upstream.timeout);
    let handler = Arc::new(Handler::new(upstream, DnsCache::new(config.cache.size)));

    // Fail fast: a TLS stack that cannot start means a broken environment,
    // even if no list is fetched over HTTPS today.
    let loader = ListLoader::new(Limits::default()).context("initializing TLS")?;
    let reloader = Reloader::start(Arc::clone(&handler), loader, config.clone(), |var| {
        std::env::var(var).ok()
    })
    .await?;
    // Kept until shutdown: the reload loop stops when every sender is gone.
    let (reload_now, reload_requests) = mpsc::channel(1);
    #[cfg(unix)]
    tokio::spawn(forward_sighup(reload_now.clone()));
    tokio::spawn(reloader.run(CONFIG_POLL_INTERVAL, reload_requests));

    let listen = config.server.listen;
    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("binding UDP {listen}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding TCP {listen}"))?;
    tracing::info!(%listen, upstream = %config.upstream.server, "dns-rs started");

    tokio::select! {
        result = serve_udp(udp, Arc::clone(&handler)) => result.context("UDP server")?,
        result = serve_tcp(tcp, handler) => result.context("TCP server")?,
        () = shutdown_signal() => tracing::info!("shutting down"),
    }
    drop(reload_now);
    Ok(())
}

/// Turns each SIGHUP into an immediate configuration reload. Signals that
/// arrive while a reload is pending are merged into it.
#[cfg(unix)]
async fn forward_sighup(reload_now: mpsc::Sender<()>) {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(mut hangups) => {
            while hangups.recv().await.is_some() {
                let _ = reload_now.try_send(());
            }
        }
        Err(error) => tracing::error!(%error, "cannot listen for SIGHUP"),
    }
}

/// Resolves on Ctrl-C, or on SIGTERM as sent by container runtimes.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
