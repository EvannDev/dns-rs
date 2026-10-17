//! dns-rs: a network-wide DNS sinkhole, built to run as stateless replicas.

pub mod blocking;
pub mod cache;
pub mod config;
pub mod filter;
pub mod forward;
pub mod handler;
pub mod http;
pub mod lists;
pub mod local;
pub mod metrics;
pub mod query_log;
pub mod reload;
pub mod server;
pub mod sources;
pub mod status;
pub mod upstream;
pub mod wire;
