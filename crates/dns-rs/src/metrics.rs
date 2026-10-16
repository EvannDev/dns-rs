//! Prometheus metrics, served in the OpenMetrics text format.
//!
//! Each replica exposes its own counters; Prometheus sums them. Label values
//! are bounded: nothing a client sends can create new series (ADR 0002).

use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::{Registry, Unit};

use crate::handler::Source;

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

pub struct Metrics {
    registry: Registry,
    queries: Family<QueryLabels, Counter>,
    durations: Family<SourceLabels, Histogram, fn() -> Histogram>,
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
        Self {
            registry,
            queries,
            durations,
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
}
