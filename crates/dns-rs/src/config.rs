//! Declarative configuration: a TOML file named by `DNS_RS_CONFIG`, whose
//! values `DNS_RS_*` environment variables can override one by one.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;

use crate::blocking::{BlockingMode, Policy};
use crate::filter::{FilterBuilder, Rule};
use crate::lists::{BareDomains, ParsedList, is_valid_domain};

const DNS_PORT: u16 = 53;

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub blocking: BlockingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Address the UDP and TCP listeners bind to.
    pub listen: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], DNS_PORT)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamConfig {
    /// Resolver queries are forwarded to; the port defaults to 53.
    #[serde(deserialize_with = "deserialize_dns_server")]
    pub server: SocketAddr,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            server: SocketAddr::from(([1, 1, 1, 1], DNS_PORT)),
            timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Maximum number of cached responses.
    pub size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { size: 10_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlockingConfig {
    pub mode: BlockingMode,
    /// Blocklists to subscribe to.
    pub lists: Vec<ListConfig>,
    /// `example.com` blocks that name, `*.example.com` it and its subdomains.
    pub deny: Vec<String>,
    /// Same syntax as `deny`; always wins over it.
    pub allow: Vec<String>,
    pub deny_regex: Vec<String>,
    pub allow_regex: Vec<String>,
}

/// A blocklist subscription: a URL, or `{ url = "…", wildcard = true }` when
/// the list's bare domains also cover their subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListConfig {
    pub source: ListSource,
    pub bare_domains: BareDomains,
}

impl From<ListSource> for ListConfig {
    fn from(source: ListSource) -> Self {
        Self {
            source,
            bare_domains: BareDomains::Exact,
        }
    }
}

/// The table form of a list entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListTable {
    url: ListSource,
    #[serde(default)]
    wildcard: bool,
}

impl<'de> Deserialize<'de> for ListConfig {
    // Hand-written rather than `#[serde(untagged)]`, whose errors would hide
    // the cause ("did not match any variant") behind a generic message.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ListConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a list URL, or a table { url = \"…\", wildcard = true }")
            }

            fn visit_str<E: serde::de::Error>(self, url: &str) -> Result<ListConfig, E> {
                ListSource::try_from(url.to_owned())
                    .map(ListConfig::from)
                    .map_err(E::custom)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<ListConfig, A::Error> {
                let table =
                    ListTable::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(ListConfig {
                    source: table.url,
                    bare_domains: if table.wildcard {
                        BareDomains::WithSubdomains
                    } else {
                        BareDomains::Exact
                    },
                })
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Where a blocklist is fetched from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub enum ListSource {
    /// `file:///absolute/path`
    File(PathBuf),
    /// `http://…` or `https://…`
    Http(String),
}

impl std::fmt::Display for ListSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "file://{}", path.display()),
            Self::Http(url) => f.write_str(url),
        }
    }
}

impl ListSource {
    /// Plain HTTP: a tampered list could inject `@@` exceptions and unblock
    /// domains, so these sources deserve a warning.
    #[must_use]
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Http(url) if url.starts_with("http://"))
    }
}

impl TryFrom<String> for ListSource {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(path) = value.strip_prefix("file://") {
            let path = PathBuf::from(path);
            return if path.is_absolute() {
                Ok(Self::File(path))
            } else {
                Err(format!(
                    "list {value:?}: file path must be absolute (file:///…)"
                ))
            };
        }
        if value.starts_with("https://") || value.starts_with("http://") {
            return Ok(Self::Http(value));
        }
        Err(format!(
            "list {value:?}: unsupported source, expected file://, http:// or https://"
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config file: {0}")]
    Parse(String),
    #[error("invalid value {value:?} for {var}: {reason}")]
    Env {
        var: &'static str,
        value: String,
        reason: String,
    },
    #[error("invalid {field}: {reason}")]
    Invalid { field: String, reason: String },
}

impl Config {
    /// Loads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::load(|var| std::env::var(var).ok())
    }

    /// Reads the file named by `DNS_RS_CONFIG` (defaults if unset), applies
    /// `DNS_RS_*` overrides, then validates the result.
    pub fn load(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut config = match lookup("DNS_RS_CONFIG") {
            Some(path) => {
                let path = PathBuf::from(path);
                let text = std::fs::read_to_string(&path)
                    .map_err(|source| ConfigError::Read { path, source })?;
                parse_toml(&text)?
            }
            None => Self::default(),
        };
        config.apply_env(&lookup)?;
        config.validate()?;
        Ok(config)
    }

    /// Parses and validates a TOML document.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config = parse_toml(text)?;
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self, lookup: &impl Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        if let Some(listen) = env_value(lookup, "DNS_RS_LISTEN")? {
            self.server.listen = listen;
        }
        if let Some(DnsServer(server)) = env_value(lookup, "DNS_RS_UPSTREAM")? {
            self.upstream.server = server;
        }
        if let Some(ms) = env_value(lookup, "DNS_RS_UPSTREAM_TIMEOUT_MS")? {
            self.upstream.timeout = Duration::from_millis(ms);
        }
        if let Some(size) = env_value(lookup, "DNS_RS_CACHE_SIZE")? {
            self.cache.size = size;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.upstream.timeout.is_zero() {
            return Err(invalid("upstream.timeout", "must be greater than zero"));
        }
        let blocking = &self.blocking;
        for (field, patterns) in [
            ("blocking.deny", &blocking.deny),
            ("blocking.allow", &blocking.allow),
        ] {
            for pattern in patterns {
                let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
                if !is_valid_domain(domain) {
                    return Err(invalid(
                        field,
                        format!("{pattern:?} is not a domain or *.domain"),
                    ));
                }
            }
        }
        for (field, patterns) in [
            ("blocking.deny_regex", &blocking.deny_regex),
            ("blocking.allow_regex", &blocking.allow_regex),
        ] {
            for pattern in patterns {
                Regex::new(pattern)
                    .map_err(|error| invalid(field, format!("{pattern:?}: {error}")))?;
            }
        }
        Ok(())
    }
}

impl BlockingConfig {
    /// The policy combining these rules with the rules of loaded `lists`.
    pub fn policy<'a>(
        &self,
        lists: impl IntoIterator<Item = &'a ParsedList>,
    ) -> Result<Policy, ConfigError> {
        let mut builder = FilterBuilder::new();
        for list in lists {
            for rule in &list.deny {
                builder.deny(rule.clone());
            }
            for rule in &list.allow {
                builder.allow(rule.clone());
            }
        }
        for pattern in &self.deny {
            builder.deny(Rule::from_pattern(pattern));
        }
        for pattern in &self.allow {
            builder.allow(Rule::from_pattern(pattern));
        }
        for pattern in &self.deny_regex {
            builder.deny(Rule::Regex(pattern.clone()));
        }
        for pattern in &self.allow_regex {
            builder.allow(Rule::Regex(pattern.clone()));
        }
        let filter = builder
            .build()
            .map_err(|error| invalid("blocking regex", error.to_string()))?;
        Ok(Policy {
            filter,
            mode: self.mode,
        })
    }
}

fn parse_toml(text: &str) -> Result<Config, ConfigError> {
    toml::from_str(text).map_err(|error| ConfigError::Parse(error.to_string()))
}

fn invalid(field: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

/// The parsed value of environment variable `var`, if set.
fn env_value<T>(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &'static str,
) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let Some(value) = lookup(var) else {
        return Ok(None);
    };
    match value.trim().parse() {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) => Err(ConfigError::Env {
            var,
            reason: error.to_string(),
            value,
        }),
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

fn deserialize_dns_server<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SocketAddr, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse::<DnsServer>()
        .map(|server| server.0)
        .map_err(|error| serde::de::Error::custom(format!("{text:?}: {error}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::*;
    use crate::filter::{Rule, Verdict};

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |var| vars.get(var).cloned()
    }

    fn invalid(text: &str) -> String {
        Config::from_toml(text).unwrap_err().to_string()
    }

    #[test]
    fn empty_document_gives_defaults() {
        let config = Config::from_toml("").unwrap();

        assert_eq!(config.server.listen, "0.0.0.0:53".parse().unwrap());
        assert_eq!(config.upstream.server, "1.1.1.1:53".parse().unwrap());
        assert_eq!(config.upstream.timeout, Duration::from_secs(2));
        assert_eq!(config.cache.size, 10_000);
        assert_eq!(config.blocking, BlockingConfig::default());
        assert_eq!(config.blocking.mode, BlockingMode::Null);
    }

    #[test]
    fn full_document_is_parsed() {
        let config = Config::from_toml(
            r#"
            [server]
            listen = "127.0.0.1:5300"

            [upstream]
            server = "[2620:fe::fe]:53"
            timeout = "500ms"

            [cache]
            size = 42

            [blocking]
            mode = "nxdomain"
            lists = ["https://example.org/hosts", "file:///etc/dns-rs/mine.txt"]
            deny = ["ads.example.com", "*.tracker.net"]
            allow = ["*.cdn.example.com"]
            deny_regex = ['^ad[0-9]+\.']
            allow_regex = ['^good\.']
            "#,
        )
        .unwrap();

        assert_eq!(config.server.listen, "127.0.0.1:5300".parse().unwrap());
        assert_eq!(config.upstream.server, "[2620:fe::fe]:53".parse().unwrap());
        assert_eq!(config.upstream.timeout, Duration::from_millis(500));
        assert_eq!(config.cache.size, 42);
        let blocking = config.blocking;
        assert_eq!(blocking.mode, BlockingMode::NxDomain);
        assert_eq!(
            blocking.lists,
            vec![
                ListSource::Http("https://example.org/hosts".to_owned()).into(),
                ListSource::File("/etc/dns-rs/mine.txt".into()).into(),
            ]
        );
        assert_eq!(blocking.deny, ["ads.example.com", "*.tracker.net"]);
        assert_eq!(blocking.allow, ["*.cdn.example.com"]);
        assert_eq!(blocking.deny_regex, [r"^ad[0-9]+\."]);
        assert_eq!(blocking.allow_regex, [r"^good\."]);
    }

    #[test]
    fn upstream_without_port_defaults_to_53() {
        let config = Config::from_toml("[upstream]\nserver = \"9.9.9.9\"").unwrap();

        assert_eq!(config.upstream.server, "9.9.9.9:53".parse().unwrap());
    }

    // A typo must not silently fall back to a default.
    #[test]
    fn unknown_field_is_rejected() {
        let error = invalid("[blocking]\ndenny = [\"ads.example.com\"]");

        assert!(error.contains("denny"), "{error}");
    }

    #[test]
    fn unknown_blocking_mode_is_rejected() {
        let error = invalid("[blocking]\nmode = \"sinkhole\"");

        assert!(error.contains("sinkhole"), "{error}");
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let error = invalid("[upstream]\ntimeout = \"0s\"");

        assert!(error.contains("timeout"), "{error}");
    }

    #[test]
    fn invalid_regex_is_rejected_and_named() {
        let error = invalid("[blocking]\ndeny_regex = ['ok', '(']");

        assert!(error.contains("deny_regex"), "{error}");
        assert!(error.contains('('), "{error}");
    }

    #[test]
    fn invalid_domain_pattern_is_rejected_and_named() {
        let error = invalid("[blocking]\nallow = ['not a domain']");

        assert!(error.contains("allow"), "{error}");
        assert!(error.contains("not a domain"), "{error}");
    }

    #[test]
    fn unsupported_list_scheme_is_rejected() {
        let error = invalid("[blocking]\nlists = ['ftp://example.org/hosts']");

        assert!(error.contains("ftp://example.org/hosts"), "{error}");
    }

    #[test]
    fn relative_file_list_is_rejected() {
        let error = invalid("[blocking]\nlists = ['file://lists/mine.txt']");

        assert!(error.contains("absolute"), "{error}");
    }

    fn lists(toml: &str) -> Vec<ListConfig> {
        Config::from_toml(&format!("[blocking]\nlists = {toml}"))
            .unwrap()
            .blocking
            .lists
    }

    #[test]
    fn list_given_as_a_string_has_exact_bare_domains() {
        assert_eq!(
            lists("['https://example.org/hosts']"),
            [ListConfig {
                source: ListSource::Http("https://example.org/hosts".to_owned()),
                bare_domains: BareDomains::Exact,
            }]
        );
    }

    #[test]
    fn wildcard_list_covers_subdomains_of_bare_domains() {
        assert_eq!(
            lists("[{ url = 'https://big.oisd.nl/domainswild2', wildcard = true }]"),
            [ListConfig {
                source: ListSource::Http("https://big.oisd.nl/domainswild2".to_owned()),
                bare_domains: BareDomains::WithSubdomains,
            }]
        );
    }

    #[test]
    fn list_table_without_wildcard_is_exact() {
        assert_eq!(
            lists("[{ url = 'file:///etc/dns-rs/mine.txt' }]"),
            [ListSource::File("/etc/dns-rs/mine.txt".into()).into()]
        );
    }

    #[test]
    fn string_and_table_entries_can_be_mixed() {
        assert_eq!(
            lists(
                "['https://a.example/hosts', { url = 'https://b.example/list', wildcard = true }]"
            ),
            [
                ListConfig {
                    source: ListSource::Http("https://a.example/hosts".to_owned()),
                    bare_domains: BareDomains::Exact,
                },
                ListConfig {
                    source: ListSource::Http("https://b.example/list".to_owned()),
                    bare_domains: BareDomains::WithSubdomains,
                },
            ]
        );
    }

    #[test]
    fn unknown_key_in_list_table_is_rejected() {
        let error =
            invalid("[blocking]\nlists = [{ url = 'https://a.example/', wildcards = true }]");

        assert!(error.contains("wildcards"), "{error}");
    }

    #[test]
    fn list_table_without_url_is_rejected() {
        let error = invalid("[blocking]\nlists = [{ wildcard = true }]");

        assert!(error.contains("url"), "{error}");
    }

    #[test]
    fn invalid_url_in_list_table_is_reported() {
        let error = invalid("[blocking]\nlists = [{ url = 'ftp://a.example/', wildcard = true }]");

        assert!(error.contains("ftp://a.example/"), "{error}");
    }

    #[test]
    fn list_source_displays_as_configured() {
        for text in ["file:///etc/dns-rs/mine.txt", "https://example.org/hosts"] {
            let source = ListSource::try_from(text.to_owned()).unwrap();

            assert_eq!(source.to_string(), text);
        }
    }

    #[test]
    fn only_plain_http_lists_are_insecure() {
        let source = |text: &str| ListSource::try_from(text.to_owned()).unwrap();

        assert!(source("http://example.org/hosts").is_insecure());
        assert!(!source("https://example.org/hosts").is_insecure());
        assert!(!source("file:///etc/dns-rs/mine.txt").is_insecure());
    }

    #[test]
    fn without_config_file_defaults_apply() {
        let config = Config::load(env(&[])).unwrap();

        assert_eq!(config, Config::default());
    }

    #[test]
    fn config_file_is_read_from_dns_rs_config() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "[cache]\nsize = 7").unwrap();
        let path = file.path().to_str().unwrap();

        let config = Config::load(env(&[("DNS_RS_CONFIG", path)])).unwrap();

        assert_eq!(config.cache.size, 7);
    }

    #[test]
    fn missing_config_file_is_an_error_naming_it() {
        let error = Config::load(env(&[("DNS_RS_CONFIG", "/nonexistent/dns-rs.toml")]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("/nonexistent/dns-rs.toml"), "{error}");
    }

    #[test]
    fn environment_overrides_the_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[server]\nlisten = \"127.0.0.1:5300\"\n[cache]\nsize = 7"
        )
        .unwrap();
        let path = file.path().to_str().unwrap();

        let config = Config::load(env(&[
            ("DNS_RS_CONFIG", path),
            ("DNS_RS_LISTEN", "127.0.0.1:5400"),
            ("DNS_RS_UPSTREAM", "9.9.9.9"),
            ("DNS_RS_UPSTREAM_TIMEOUT_MS", "300"),
        ]))
        .unwrap();

        assert_eq!(config.server.listen, "127.0.0.1:5400".parse().unwrap());
        assert_eq!(config.upstream.server, "9.9.9.9:53".parse().unwrap());
        assert_eq!(config.upstream.timeout, Duration::from_millis(300));
        assert_eq!(config.cache.size, 7);
    }

    #[test]
    fn invalid_environment_value_names_the_variable() {
        let error = Config::load(env(&[("DNS_RS_CACHE_SIZE", "lots")]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("DNS_RS_CACHE_SIZE"), "{error}");
        assert!(error.contains("lots"), "{error}");
    }

    #[test]
    fn zero_timeout_from_environment_is_rejected() {
        assert!(Config::load(env(&[("DNS_RS_UPSTREAM_TIMEOUT_MS", "0")])).is_err());
    }

    #[test]
    fn policy_combines_config_rules_and_lists() {
        let config = Config::from_toml(
            r#"
            [blocking]
            mode = "refused"
            deny = ["*.tracker.net"]
            allow = ["ok.ads.example"]
            deny_regex = ['^ad[0-9]+\.']
            allow_regex = ['^ad1\.']
            "#,
        )
        .unwrap();
        let list = ParsedList {
            deny: vec![Rule::Subtree("ads.example".to_owned())],
            allow: vec![Rule::Exact("fine.ads.example".to_owned())],
            skipped: 0,
        };

        let policy = config.blocking.policy(&[list]).unwrap();

        assert_eq!(policy.mode, BlockingMode::Refused);
        for (domain, verdict) in [
            ("x.tracker.net", Verdict::Blocked),
            ("x.ads.example", Verdict::Blocked),
            ("ok.ads.example", Verdict::Allowed),
            ("fine.ads.example", Verdict::Allowed),
            ("ad2.example.com", Verdict::Blocked),
            ("ad1.example.com", Verdict::Allowed),
            ("example.com", Verdict::Allowed),
        ] {
            assert_eq!(policy.filter.check(domain), verdict, "{domain}");
        }
    }
}
