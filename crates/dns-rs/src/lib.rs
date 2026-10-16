//! dns-rs: a network-wide DNS sinkhole, built to run as stateless replicas.

pub mod cache;
pub mod config;
pub mod handler;
pub mod server;
pub mod upstream;
pub mod wire;
