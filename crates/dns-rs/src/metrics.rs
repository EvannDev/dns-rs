//! Prometheus metrics, served in the OpenMetrics text format.
//!
//! Each replica exposes its own counters; Prometheus sums them. Label values
//! are bounded: nothing a client sends can create new series (ADR 0002).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::{ConstGauge, Gauge};
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::{Registry, Unit};
use reqwest::Url;

use crate::config::ListSource;
use crate::handler::Source;
use crate::sources::FetchError;

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct QueryLabels {
    source: &'static str,
    rcode: &'static str,
    r#type: &'static str,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SourceLabels {
    source: &'static str,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ListLabels {
    list: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ListFailureLabels {
    list: String,
    reason: &'static str,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: &'static str,
}

const FAILURE_REASONS: [&str; 4] = ["timeout", "too_large", "status", "failed"];

pub struct Metrics {
    registry: Registry,
    queries: Family<QueryLabels, Counter>,
    durations: Family<SourceLabels, Histogram, fn() -> Histogram>,
    blocking_rules: Gauge,
    list_rules: Family<ListLabels, Gauge>,
    list_last_success: Family<ListLabels, Gauge>,
    list_failures: Family<ListFailureLabels, Counter>,
    config_reloads: Family<ResultLabels, Counter>,
    config_valid: Gauge,
}

/// A gauge computed at scrape time.
struct CallbackGauge {
    name: &'static str,
    help: &'static str,
    value: Box<dyn Fn() -> usize + Send + Sync>,
}

impl std::fmt::Debug for CallbackGauge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackGauge")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Collector for CallbackGauge {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let gauge = ConstGauge::new(i64::try_from((self.value)()).unwrap_or(i64::MAX));
        let metric = encoder.encode_descriptor(self.name, self.help, None, gauge.metric_type())?;
        gauge.encode(metric)
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("dns_rs");
        registry.register(
            "build",
            "dns-rs build information",
            Info::new(vec![("version", env!("CARGO_PKG_VERSION"))]),
        );
        let queries = Family::<QueryLabels, Counter>::default();
        registry.register(
            "queries",
            "DNS queries answered, by where the answer came from",
            queries.clone(),
        );
        let durations = Family::<SourceLabels, Histogram>::new_with_constructor(
            new_duration_histogram as fn() -> Histogram,
        );
        registry.register_with_unit(
            "query_duration",
            "Time to answer a DNS query",
            Unit::Seconds,
            durations.clone(),
        );
        let blocking_rules = Gauge::default();
        registry.register(
            "blocking_rules",
            "Deny rules in the blocking policy in force",
            blocking_rules.clone(),
        );
        let list_rules = Family::<ListLabels, Gauge>::default();
        registry.register(
            "blocklist_rules",
            "Deny rules from each blocklist, as last loaded",
            list_rules.clone(),
        );
        let list_last_success = Family::<ListLabels, Gauge>::default();
        registry.register(
            "blocklist_last_success_timestamp_seconds",
            "When each blocklist last loaded successfully, as a Unix time",
            list_last_success.clone(),
        );
        let list_failures = Family::<ListFailureLabels, Counter>::default();
        registry.register(
            "blocklist_failures",
            "Blocklist loads that failed, by reason",
            list_failures.clone(),
        );
        let config_reloads = Family::<ResultLabels, Counter>::default();
        registry.register(
            "config_reloads",
            "Configuration changes applied or rejected",
            config_reloads.clone(),
        );
        let config_valid = Gauge::default();
        config_valid.set(1);
        registry.register(
            "config_valid",
            "1 if the configuration file, as last read, is valid; 0 otherwise",
            config_valid.clone(),
        );
        Self {
            registry,
            queries,
            durations,
            blocking_rules,
            list_rules,
            list_last_success,
            list_failures,
            config_reloads,
            config_valid,
        }
    }

    /// Records one answered query.
    pub fn record_query(
        &self,
        source: Source,
        rcode: ResponseCode,
        record_type: Option<RecordType>,
        elapsed: Duration,
    ) {
        let source = source_label(source);
        self.queries
            .get_or_create(&QueryLabels {
                source,
                rcode: rcode_label(rcode),
                r#type: record_type.map_or("none", type_label),
            })
            .inc();
        self.durations
            .get_or_create(&SourceLabels { source })
            .observe(elapsed.as_secs_f64());
    }

    /// The registry in the OpenMetrics text format.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut text = String::new();
        // Writing to a String cannot fail.
        let _ = prometheus_client::encoding::text::encode(&mut text, &self.registry);
        text
    }
}

/// The list's URL without credentials, query or fragment: /metrics has no
/// authentication, and private list URLs may carry a token.
fn list_label(source: &ListSource) -> String {
    match source {
        ListSource::File(_) => source.to_string(),
        ListSource::Http(url) => match Url::parse(url) {
            Ok(mut url) => {
                let _ = url.set_username("");
                let _ = url.set_password(None);
                url.set_query(None);
                url.set_fragment(None);
                url.to_string()
            }
            // Validation accepted it, but it does not parse: show nothing of it.
            Err(_) => "unparsable-url".to_owned(),
        },
    }
}

fn saturating_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// 50 µs (a cached or blocked answer) to about 1.6 s (a slow upstream).
fn new_duration_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.000_05, 2.0, 16))
}

fn source_label(source: Source) -> &'static str {
    match source {
        Source::Cache => "cache",
        Source::Upstream => "upstream",
        Source::Blocked => "blocked",
        Source::Rejected => "rejected",
        Source::Failed => "failed",
    }
}

fn rcode_label(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        _ => "other",
    }
}

/// Common types get their own label; any other shares `other`.
fn type_label(record_type: RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::ANY => "ANY",
        RecordType::CAA => "CAA",
        RecordType::CNAME => "CNAME",
        RecordType::DNSKEY => "DNSKEY",
        RecordType::DS => "DS",
        RecordType::HTTPS => "HTTPS",
        RecordType::MX => "MX",
        RecordType::NS => "NS",
        RecordType::PTR => "PTR",
        RecordType::SOA => "SOA",
        RecordType::SRV => "SRV",
        RecordType::SVCB => "SVCB",
        RecordType::TXT => "TXT",
        _ => "other",
    }
}

/// Outcome of a configuration reload that changed something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadResult {
    Applied,
    Rejected,
}

impl Metrics {
    /// Exposes `dns_rs_cache_entries`, read from `entries` at each scrape.
    pub fn register_cache_entries(&mut self, entries: impl Fn() -> usize + Send + Sync + 'static) {
        self.registry.register_collector(Box::new(CallbackGauge {
            name: "cache_entries",
            help: "Responses held in the DNS cache",
            value: Box::new(entries),
        }));
    }

    /// Number of deny rules in the policy in force.
    pub fn set_blocking_rules(&self, rules: usize) {
        self.blocking_rules.set(saturating_i64(rules));
    }

    /// A list loaded with `rules` deny rules at `at`.
    pub fn record_list_loaded(&self, source: &ListSource, rules: usize, at: SystemTime) {
        let labels = ListLabels {
            list: list_label(source),
        };
        self.list_rules
            .get_or_create(&labels)
            .set(saturating_i64(rules));
        let seconds = at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        self.list_last_success
            .get_or_create(&labels)
            .set(i64::try_from(seconds).unwrap_or(i64::MAX));
    }

    /// A list that failed to load.
    pub fn record_list_failed(&self, source: &ListSource, error: &FetchError) {
        let reason = match error {
            FetchError::Timeout => "timeout",
            FetchError::TooLarge(_) => "too_large",
            FetchError::Status(_) => "status",
            FetchError::Failed(_) => "failed",
        };
        self.list_failures
            .get_or_create(&ListFailureLabels {
                list: list_label(source),
                reason,
            })
            .inc();
    }

    /// Drops the series of a list no longer configured.
    pub fn forget_list(&self, source: &ListSource) {
        let list = list_label(source);
        let labels = ListLabels { list: list.clone() };
        self.list_rules.remove(&labels);
        self.list_last_success.remove(&labels);
        for reason in FAILURE_REASONS {
            self.list_failures.remove(&ListFailureLabels {
                list: list.clone(),
                reason,
            });
        }
    }

    pub fn record_config_reload(&self, result: ReloadResult) {
        let result = match result {
            ReloadResult::Applied => "applied",
            ReloadResult::Rejected => "rejected",
        };
        self.config_reloads
            .get_or_create(&ResultLabels { result })
            .inc();
    }

    /// Whether the configuration file, as last read, is valid.
    pub fn set_config_valid(&self, valid: bool) {
        self.config_valid.set(i64::from(valid));
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        metrics: &Metrics,
        source: Source,
        rcode: ResponseCode,
        record_type: Option<RecordType>,
    ) {
        metrics.record_query(source, rcode, record_type, Duration::from_micros(500));
    }

    #[test]
    fn queries_are_counted_by_source_rcode_and_type() {
        let metrics = Metrics::new();

        record(
            &metrics,
            Source::Blocked,
            ResponseCode::NoError,
            Some(RecordType::A),
        );
        record(
            &metrics,
            Source::Blocked,
            ResponseCode::NoError,
            Some(RecordType::A),
        );
        record(
            &metrics,
            Source::Upstream,
            ResponseCode::NXDomain,
            Some(RecordType::AAAA),
        );

        let text = metrics.encode();
        assert!(
            text.contains(r#"dns_rs_queries_total{source="blocked",rcode="NOERROR",type="A"} 2"#),
            "{text}"
        );
        assert!(
            text.contains(
                r#"dns_rs_queries_total{source="upstream",rcode="NXDOMAIN",type="AAAA"} 1"#
            ),
            "{text}"
        );
    }

    // A client can send any of 65536 types: unusual ones share one series.
    #[test]
    fn unusual_record_types_share_one_label() {
        let metrics = Metrics::new();

        record(
            &metrics,
            Source::Upstream,
            ResponseCode::NoError,
            Some(RecordType::Unknown(65280)),
        );
        record(
            &metrics,
            Source::Upstream,
            ResponseCode::NoError,
            Some(RecordType::NULL),
        );

        let text = metrics.encode();
        assert!(
            text.contains(
                r#"dns_rs_queries_total{source="upstream",rcode="NOERROR",type="other"} 2"#
            ),
            "{text}"
        );
    }

    #[test]
    fn common_record_types_have_their_own_label() {
        let metrics = Metrics::new();

        for record_type in [RecordType::HTTPS, RecordType::TXT, RecordType::PTR] {
            record(
                &metrics,
                Source::Cache,
                ResponseCode::NoError,
                Some(record_type),
            );
        }

        let text = metrics.encode();
        for name in ["HTTPS", "TXT", "PTR"] {
            assert!(
                text.contains(&format!(r#"type="{name}"}} 1"#)),
                "{name}: {text}"
            );
        }
    }

    #[test]
    fn unusual_rcodes_share_one_label() {
        let metrics = Metrics::new();

        record(
            &metrics,
            Source::Upstream,
            ResponseCode::BADCOOKIE,
            Some(RecordType::A),
        );

        let text = metrics.encode();
        assert!(text.contains(r#"rcode="other",type="A"} 1"#), "{text}");
    }

    #[test]
    fn request_without_question_has_type_none() {
        let metrics = Metrics::new();

        record(&metrics, Source::Rejected, ResponseCode::FormErr, None);

        let text = metrics.encode();
        assert!(
            text.contains(
                r#"dns_rs_queries_total{source="rejected",rcode="FORMERR",type="none"} 1"#
            ),
            "{text}"
        );
    }

    #[test]
    fn durations_are_observed_per_source() {
        let metrics = Metrics::new();

        metrics.record_query(
            Source::Cache,
            ResponseCode::NoError,
            Some(RecordType::A),
            Duration::from_micros(40),
        );
        metrics.record_query(
            Source::Upstream,
            ResponseCode::NoError,
            Some(RecordType::A),
            Duration::from_millis(30),
        );

        let text = metrics.encode();
        assert!(
            text.contains(r#"dns_rs_query_duration_seconds_count{source="cache"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"dns_rs_query_duration_seconds_count{source="upstream"} 1"#),
            "{text}"
        );
        // 40 µs falls in the first bucket (50 µs); 30 ms does not.
        assert!(
            text.contains(r#"dns_rs_query_duration_seconds_bucket{le="0.00005",source="cache"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(
                r#"dns_rs_query_duration_seconds_bucket{le="0.00005",source="upstream"} 0"#
            ),
            "{text}"
        );
    }

    #[test]
    fn build_info_carries_the_version() {
        let text = Metrics::new().encode();

        assert!(
            text.contains(&format!(
                r#"dns_rs_build_info{{version="{}"}} 1"#,
                env!("CARGO_PKG_VERSION")
            )),
            "{text}"
        );
    }

    #[test]
    fn output_is_terminated_openmetrics() {
        assert!(Metrics::new().encode().ends_with("# EOF\n"));
    }

    mod state {
        use std::time::UNIX_EPOCH;

        use super::*;

        fn source(url: &str) -> ListSource {
            ListSource::try_from(url.to_owned()).unwrap()
        }

        #[test]
        fn blocking_rules_are_exposed() {
            let metrics = Metrics::new();

            metrics.set_blocking_rules(1234);

            assert!(metrics.encode().contains("dns_rs_blocking_rules 1234"));
        }

        #[test]
        fn loaded_list_exposes_its_rules_and_success_time() {
            let metrics = Metrics::new();
            let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

            metrics.record_list_loaded(&source("https://lists.example/hosts"), 500, at);

            let text = metrics.encode();
            assert!(
                text.contains(r#"dns_rs_blocklist_rules{list="https://lists.example/hosts"} 500"#),
                "{text}"
            );
            assert!(
                text.contains(r#"dns_rs_blocklist_last_success_timestamp_seconds{list="https://lists.example/hosts"} 1700000000"#),
                "{text}"
            );
        }

        #[test]
        fn list_failures_are_counted_by_reason() {
            let metrics = Metrics::new();
            let list = source("https://lists.example/hosts");

            metrics.record_list_failed(&list, &FetchError::Timeout);
            metrics.record_list_failed(&list, &FetchError::Timeout);
            metrics.record_list_failed(&list, &FetchError::TooLarge(10));
            metrics.record_list_failed(&list, &FetchError::Status(404));
            metrics.record_list_failed(&list, &FetchError::Failed("dns error".to_owned()));

            let text = metrics.encode();
            for (reason, count) in [
                ("timeout", 2),
                ("too_large", 1),
                ("status", 1),
                ("failed", 1),
            ] {
                let series = format!(
                    r#"dns_rs_blocklist_failures_total{{list="https://lists.example/hosts",reason="{reason}"}} {count}"#
                );
                assert!(text.contains(&series), "{series} missing from {text}");
            }
        }

        // /metrics has no authentication: a private list URL must not leak
        // its credentials or token.
        #[test]
        fn list_label_drops_credentials_query_and_fragment() {
            let metrics = Metrics::new();

            metrics.set_blocking_rules(0);
            metrics.record_list_loaded(
                &source("https://user:secret@lists.example/hosts?token=abc#part"),
                1,
                UNIX_EPOCH,
            );

            let text = metrics.encode();
            assert!(
                text.contains(r#"list="https://lists.example/hosts""#),
                "{text}"
            );
            for secret in ["user", "secret", "token", "abc", "part"] {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }

        #[test]
        fn file_list_label_is_its_url() {
            let metrics = Metrics::new();

            metrics.record_list_loaded(&source("file:///etc/dns-rs/mine.txt"), 3, UNIX_EPOCH);

            assert!(
                metrics
                    .encode()
                    .contains(r#"list="file:///etc/dns-rs/mine.txt""#)
            );
        }

        #[test]
        fn forgotten_list_has_no_series_left() {
            let metrics = Metrics::new();
            let list = source("https://lists.example/hosts");
            metrics.record_list_loaded(&list, 500, UNIX_EPOCH);
            metrics.record_list_failed(&list, &FetchError::Timeout);

            metrics.forget_list(&list);

            assert!(!metrics.encode().contains("lists.example"));
        }

        #[test]
        fn config_reloads_are_counted_by_result() {
            let metrics = Metrics::new();

            metrics.record_config_reload(ReloadResult::Applied);
            metrics.record_config_reload(ReloadResult::Applied);
            metrics.record_config_reload(ReloadResult::Rejected);

            let text = metrics.encode();
            assert!(
                text.contains(r#"dns_rs_config_reloads_total{result="applied"} 2"#),
                "{text}"
            );
            assert!(
                text.contains(r#"dns_rs_config_reloads_total{result="rejected"} 1"#),
                "{text}"
            );
        }

        #[test]
        fn config_is_valid_until_said_otherwise() {
            let metrics = Metrics::new();
            let before = metrics.encode();

            metrics.set_config_valid(false);

            assert!(before.contains("dns_rs_config_valid 1"), "{before}");
            assert!(metrics.encode().contains("dns_rs_config_valid 0"));
        }

        #[test]
        fn cache_entries_are_read_at_each_scrape() {
            let entries = Arc::new(AtomicUsize::new(7));
            let mut metrics = Metrics::new();
            let source = Arc::clone(&entries);
            metrics.register_cache_entries(move || source.load(Ordering::Relaxed));

            let first = metrics.encode();
            entries.store(9, Ordering::Relaxed);
            let second = metrics.encode();

            assert!(first.contains("dns_rs_cache_entries 7"), "{first}");
            assert!(second.contains("dns_rs_cache_entries 9"), "{second}");
        }

        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
    }
}
