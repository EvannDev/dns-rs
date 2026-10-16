//! Runtime configuration, read from `DNS_RS_*` environment variables.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the UDP and TCP listeners bind to.
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub upstream_timeout: Duration,
    pub cache_size: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid value {value:?} for {var}: {reason}")]
pub struct ConfigError {
    var: &'static str,
    value: String,
    reason: String,
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads the configuration through `lookup`, falling back to defaults.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let timeout_ms: u64 = parse(&lookup, "DNS_RS_UPSTREAM_TIMEOUT_MS", 2000)?;
        if timeout_ms == 0 {
            return Err(ConfigError {
                var: "DNS_RS_UPSTREAM_TIMEOUT_MS",
                value: timeout_ms.to_string(),
                reason: "must be greater than zero".to_owned(),
            });
        }
        Ok(Self {
            listen: parse(
                &lookup,
                "DNS_RS_LISTEN",
                SocketAddr::from(([0, 0, 0, 0], DNS_PORT)),
            )?,
            upstream: parse(
                &lookup,
                "DNS_RS_UPSTREAM",
                DnsServer(([1, 1, 1, 1], DNS_PORT).into()),
            )?
            .0,
            upstream_timeout: Duration::from_millis(timeout_ms),
            cache_size: parse(&lookup, "DNS_RS_CACHE_SIZE", 10_000)?,
        })
    }
}

/// A DNS server address whose port defaults to 53.
struct DnsServer(SocketAddr);

impl FromStr for DnsServer {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse()
            .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, DNS_PORT)))
            .map(DnsServer)
    }
}

fn parse<T>(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: T,
) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let Some(value) = lookup(var) else {
        return Ok(default);
    };
    value.trim().parse().map_err(|error: T::Err| ConfigError {
        var,
        reason: error.to_string(),
        value,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|var| vars.get(var).cloned())
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        assert_eq!(
            config(&[]).unwrap(),
            Config {
                listen: "0.0.0.0:53".parse().unwrap(),
                upstream: "1.1.1.1:53".parse().unwrap(),
                upstream_timeout: Duration::from_secs(2),
                cache_size: 10_000,
            }
        );
    }

    #[test]
    fn variables_override_defaults() {
        let config = config(&[
            ("DNS_RS_LISTEN", "127.0.0.1:5353"),
            ("DNS_RS_UPSTREAM", "[2606:4700:4700::1111]:53"),
            ("DNS_RS_UPSTREAM_TIMEOUT_MS", "500"),
            ("DNS_RS_CACHE_SIZE", "42"),
        ])
        .unwrap();

        assert_eq!(config.listen, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(
            config.upstream,
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
        assert_eq!(config.upstream_timeout, Duration::from_millis(500));
        assert_eq!(config.cache_size, 42);
    }

    #[test]
    fn upstream_without_port_defaults_to_53() {
        let config = config(&[("DNS_RS_UPSTREAM", "9.9.9.9")]).unwrap();

        assert_eq!(config.upstream, "9.9.9.9:53".parse().unwrap());
    }

    #[test]
    fn invalid_value_names_the_variable() {
        let error = config(&[("DNS_RS_CACHE_SIZE", "lots")]).unwrap_err();

        assert!(error.to_string().contains("DNS_RS_CACHE_SIZE"), "{error}");
        assert!(error.to_string().contains("lots"), "{error}");
    }

    #[test]
    fn zero_timeout_is_rejected() {
        assert!(config(&[("DNS_RS_UPSTREAM_TIMEOUT_MS", "0")]).is_err());
    }
}
