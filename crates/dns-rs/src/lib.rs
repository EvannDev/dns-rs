//! dns-rs: a network-wide DNS sinkhole, built to run as stateless replicas.

pub mod blocking;
pub mod cache;
pub mod config;
pub mod filter;
pub mod handler;
pub mod lists;
pub mod query_log;
pub mod reload;
pub mod server;
pub mod sources;
pub mod upstream;
pub mod wire;
