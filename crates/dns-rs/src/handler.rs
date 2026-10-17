//! Turns a client request into a response: validation, cache, then upstream.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};

use crate::blocking::{BlockingMode, Policy, blocked_answer};
use crate::cache::{CacheKey, DnsCache};
use crate::filter::{Explanation, Verdict};
use crate::local::LocalRecords;
use crate::upstream::Upstream;

/// UDP payload size advertised to EDNS clients (DNS flag day 2020).
pub const EDNS_PAYLOAD: u16 = 1232;

/// Where a response came from, for the query log and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cache,
    Upstream,
    Blocked,
    /// A local record (ADR 0016).
    Local,
    /// The request was invalid or unsupported (FORMERR, NOTIMP).
    Rejected,
    /// The upstream could not answer (SERVFAIL).
    Failed,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cache => "cache",
            Self::Upstream => "upstream",
            Self::Blocked => "blocked",
            Self::Local => "local",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug)]
pub struct Resolution {
    pub response: Message,
    pub source: Source,
}

pub struct Handler<U> {
    upstream: U,
    cache: DnsCache,
    policy: ArcSwap<Policy>,
    local: ArcSwap<LocalRecords>,
}

impl<U: Upstream> Handler<U> {
    /// A handler that blocks nothing until [`Handler::set_policy`] is called.
    pub fn new(upstream: U, cache: DnsCache) -> Self {
        Self {
            upstream,
            cache,
            policy: ArcSwap::from_pointee(Policy::allow_all()),
            local: ArcSwap::from_pointee(LocalRecords::default()),
        }
    }

    /// Responses held in the cache, for metrics.
    #[must_use]
    pub fn cached_responses(&self) -> usize {
        self.cache.len()
    }

    /// Replaces the blocking policy; takes effect for the next query.
    pub fn set_policy(&self, policy: Policy) {
        self.policy.store(Arc::new(policy));
    }

    /// Replaces the local records; takes effect for the next query.
    pub fn set_local_records(&self, records: LocalRecords) {
        self.local.store(Arc::new(records));
    }

    /// Answers `request`. Never fails: errors become DNS response codes.
    pub async fn handle(&self, request: &Message) -> Resolution {
        if request.metadata.op_code != OpCode::Query {
            return resolved(reply(request, ResponseCode::NotImp), Source::Rejected);
        }
        let [question] = request.queries.as_slice() else {
            return resolved(reply(request, ResponseCode::FormErr), Source::Rejected);
        };

        // Before blocking: a name given an address on purpose is not blocked.
        if let Some(answers) = self.local.load().answer(question) {
            let mut response = reply(request, ResponseCode::NoError);
            response.metadata.authoritative = true;
            response.answers = answers;
            return resolved(response, Source::Local);
        }

        let policy = self.policy.load();
        if policy.filter.check(&question.name().to_ascii()) == Verdict::Blocked {
            let (code, answers) = blocked_answer(question, policy.mode);
            let mut response = reply(request, code);
            response.answers = answers;
            return resolved(response, Source::Blocked);
        }

        let key = CacheKey::from(question);
        if let Some(cached) = self.cache.get(&key, Instant::now()) {
            return resolved(answer(request, &cached), Source::Cache);
        }

        match self.upstream.query(&upstream_query(question)).await {
            Ok(upstream) => {
                self.cache.insert(key, &upstream, Instant::now());
                resolved(answer(request, &upstream), Source::Upstream)
            }
            Err(error) => {
                tracing::warn!(%error, name = %question.name(), "upstream query failed");
                resolved(reply(request, ResponseCode::ServFail), Source::Failed)
            }
        }
    }
}

fn resolved(response: Message, source: Source) -> Resolution {
    Resolution { response, source }
}

/// Read access to the blocking policy in force, for `/api/v1/check`.
pub trait PolicyView: Send + Sync {
    fn explain(&self, domain: &str) -> (BlockingMode, Explanation);
}

impl<U: Upstream> PolicyView for Handler<U> {
    fn explain(&self, domain: &str) -> (BlockingMode, Explanation) {
        let policy = self.policy.load();
        (policy.mode, policy.filter.explain(domain))
    }
}

/// A fresh recursive query for `question`, independent of the client's header.
fn upstream_query(question: &Query) -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(question.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    query.set_edns(edns);
    query
}

/// An empty response to `request` carrying `code`.
fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().cloned());
    if request.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        response.set_edns(edns);
    }
    response
}

/// A response to `request` carrying the records and code of `upstream`.
fn answer(request: &Message, upstream: &Message) -> Message {
    let mut response = reply(request, upstream.metadata.response_code);
    response.answers.clone_from(&upstream.answers);
    response.authorities.clone_from(&upstream.authorities);
    response.additionals.clone_from(&upstream.additionals);
    response
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::{Edns, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;
    use crate::blocking::BlockingMode;
    use crate::filter::{FilterBuilder, Rule};
    use crate::upstream::UpstreamError;

    /// Upstream double answering every A query with 192.0.2.1, or failing.
    #[derive(Default)]
    struct FakeUpstream {
        fail: bool,
        calls: AtomicUsize,
        last_query: Mutex<Option<Message>>,
    }

    impl Upstream for FakeUpstream {
        fn query(
            &self,
            query: &Message,
        ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
            std::future::ready(self.answer(query))
        }
    }

    impl FakeUpstream {
        fn answer(&self, query: &Message) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_query.lock().unwrap() = Some(query.clone());
            if self.fail {
                return Err(UpstreamError::Timeout);
            }
            let question = query.queries[0].clone();
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
            response.add_query(question);
            Ok(response)
        }
    }

    fn handler(upstream: FakeUpstream) -> Handler<FakeUpstream> {
        Handler::new(upstream, DnsCache::new(100))
    }

    fn request(id: u16, domain: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn block(handler: &Handler<FakeUpstream>, deny: &str, mode: BlockingMode) {
        let mut builder = FilterBuilder::new();
        builder.deny(Rule::from_pattern(deny));
        handler.set_policy(Policy {
            filter: builder.build().unwrap(),
            mode,
        });
    }

    mod local_records {
        use std::net::IpAddr;

        use super::*;
        use crate::local::LocalRecords;

        const NAS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        fn with_nas(handler: &Handler<FakeUpstream>) {
            handler.set_local_records(LocalRecords::new([("nas.home.arpa", NAS)], 300));
        }

        fn typed(id: u16, domain: &str, record_type: RecordType) -> Message {
            let mut msg = request(id, domain);
            msg.queries[0].set_query_type(record_type);
            msg
        }

        // ADR 0016: dns-rs alone answers, authoritatively, without the
        // upstream or the cache.
        #[tokio::test]
        async fn local_name_is_answered_authoritatively_without_the_upstream() {
            let handler = handler(FakeUpstream::default());
            with_nas(&handler);

            let resolution = handler.handle(&request(7, "nas.home.arpa.")).await;

            let response = &resolution.response;
            assert_eq!(resolution.source, Source::Local);
            assert_eq!(response.metadata.id, 7);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.metadata.authoritative);
            assert!(response.metadata.recursion_available);
            assert_eq!(
                response.answers[0].data,
                RData::A(A(Ipv4Addr::new(192, 168, 1, 10)))
            );
            assert_eq!(response.queries, request(7, "nas.home.arpa.").queries);
            assert_eq!(handler.upstream.calls.load(Ordering::SeqCst), 0);
            assert_eq!(handler.cached_responses(), 0);
        }

        // A name the operator gave an address on purpose is not blocked.
        #[tokio::test]
        async fn local_name_wins_over_a_deny_rule() {
            let handler = handler(FakeUpstream::default());
            with_nas(&handler);
            block(&handler, "*.home.arpa", BlockingMode::NxDomain);

            let resolution = handler.handle(&request(1, "nas.home.arpa.")).await;

            assert_eq!(resolution.source, Source::Local);
            assert_eq!(resolution.response.answers.len(), 1);
        }

        #[tokio::test]
        async fn other_type_of_a_local_name_gets_an_empty_noerror() {
            let handler = handler(FakeUpstream::default());
            with_nas(&handler);

            let resolution = handler
                .handle(&typed(1, "nas.home.arpa.", RecordType::MX))
                .await;

            assert_eq!(resolution.source, Source::Local);
            assert_eq!(
                resolution.response.metadata.response_code,
                ResponseCode::NoError
            );
            assert_eq!(resolution.response.answers, []);
        }

        #[tokio::test]
        async fn names_that_are_not_local_are_still_forwarded() {
            let handler = handler(FakeUpstream::default());
            with_nas(&handler);

            let resolution = handler.handle(&request(1, "x.nas.home.arpa.")).await;

            assert_eq!(resolution.source, Source::Upstream);
        }

        // The query log prints it: log pipelines may match on it.
        #[test]
        fn local_answers_are_named_local_in_the_query_log() {
            assert_eq!(Source::Local.to_string(), "local");
        }

        #[tokio::test]
        async fn replaced_records_apply_to_the_next_query() {
            let handler = handler(FakeUpstream::default());
            with_nas(&handler);

            handler.set_local_records(LocalRecords::default());
            let resolution = handler.handle(&request(1, "nas.home.arpa.")).await;

            assert_eq!(resolution.source, Source::Upstream);
        }
    }

    #[tokio::test]
    async fn blocked_domain_is_answered_locally() {
        let handler = handler(FakeUpstream::default());
        block(&handler, "*.ads.example", BlockingMode::Null);

        let resolution = handler.handle(&request(7, "x.ads.example.")).await;

        assert_eq!(resolution.source, Source::Blocked);
        assert_eq!(handler.upstream.calls.load(Ordering::SeqCst), 0);
        let response = resolution.response;
        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.queries, request(7, "x.ads.example.").queries);
        assert_eq!(response.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    }

    #[tokio::test]
    async fn blocking_mode_shapes_the_response() {
        let handler = handler(FakeUpstream::default());
        block(&handler, "ads.example", BlockingMode::NxDomain);

        let response = handler.handle(&request(7, "ads.example.")).await.response;

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn domains_not_blocked_are_still_forwarded() {
        let handler = handler(FakeUpstream::default());
        block(&handler, "ads.example", BlockingMode::Null);

        let resolution = handler.handle(&request(7, "example.com.")).await;

        assert_eq!(resolution.source, Source::Upstream);
    }

    // The filter runs before the cache: a new rule applies at once, even to
    // names answered moments ago.
    #[tokio::test]
    async fn new_policy_applies_immediately_even_to_cached_names() {
        let handler = handler(FakeUpstream::default());
        handler.handle(&request(1, "example.com.")).await;

        block(&handler, "example.com", BlockingMode::Null);
        let resolution = handler.handle(&request(2, "example.com.")).await;

        assert_eq!(resolution.source, Source::Blocked);
    }

    #[tokio::test]
    async fn policy_can_be_lifted() {
        let handler = handler(FakeUpstream::default());
        block(&handler, "example.com", BlockingMode::Null);

        handler.set_policy(Policy::allow_all());
        let resolution = handler.handle(&request(7, "example.com.")).await;

        assert_eq!(resolution.source, Source::Upstream);
    }

    #[tokio::test]
    async fn cached_responses_are_reported() {
        let handler = handler(FakeUpstream::default());

        handler.handle(&request(1, "a.example.")).await;
        handler.handle(&request(2, "b.example.")).await;
        handler.handle(&request(3, "a.example.")).await;

        assert_eq!(handler.cached_responses(), 2);
    }

    #[tokio::test]
    async fn first_query_comes_from_upstream() {
        let handler = handler(FakeUpstream::default());

        let resolution = handler.handle(&request(7, "example.com.")).await;

        assert_eq!(resolution.source, Source::Upstream);
    }

    #[tokio::test]
    async fn repeated_query_comes_from_cache() {
        let handler = handler(FakeUpstream::default());

        handler.handle(&request(1, "example.com.")).await;
        let resolution = handler.handle(&request(2, "example.com.")).await;

        assert_eq!(resolution.source, Source::Cache);
    }

    #[tokio::test]
    async fn upstream_failure_is_reported_as_failed() {
        let handler = handler(FakeUpstream {
            fail: true,
            ..FakeUpstream::default()
        });

        let resolution = handler.handle(&request(7, "example.com.")).await;

        assert_eq!(resolution.source, Source::Failed);
    }

    #[tokio::test]
    async fn invalid_request_is_reported_as_rejected() {
        let handler = handler(FakeUpstream::default());
        let empty = Message::new(7, MessageType::Query, OpCode::Query);

        let resolution = handler.handle(&empty).await;

        assert_eq!(resolution.source, Source::Rejected);
    }

    #[tokio::test]
    async fn forwards_query_and_returns_upstream_answers() {
        let handler = handler(FakeUpstream::default());

        let response = handler.handle(&request(7, "example.com.")).await.response;

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.queries, request(7, "example.com.").queries);
    }

    #[tokio::test]
    async fn response_header_matches_request() {
        let handler = handler(FakeUpstream::default());

        let response = handler.handle(&request(7, "example.com.")).await.response;

        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert!(response.metadata.recursion_desired);
        assert!(response.metadata.recursion_available);
    }

    #[tokio::test]
    async fn upstream_receives_only_the_question_with_recursion() {
        let upstream = FakeUpstream::default();
        let handler = handler(upstream);

        handler.handle(&request(7, "example.com.")).await;

        let sent = handler.upstream.last_query.lock().unwrap().clone().unwrap();
        assert_eq!(sent.queries, request(7, "example.com.").queries);
        assert!(sent.metadata.recursion_desired);
        assert_eq!(sent.metadata.message_type, MessageType::Query);
    }

    #[tokio::test]
    async fn repeated_query_is_served_from_cache() {
        let handler = handler(FakeUpstream::default());

        handler.handle(&request(1, "example.com.")).await;
        let second = handler.handle(&request(2, "example.com.")).await.response;

        assert_eq!(handler.upstream.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.metadata.id, 2);
        assert_eq!(second.answers.len(), 1);
    }

    #[tokio::test]
    async fn upstream_failure_returns_servfail() {
        let handler = handler(FakeUpstream {
            fail: true,
            ..FakeUpstream::default()
        });

        let response = handler.handle(&request(7, "example.com.")).await.response;

        assert_eq!(response.metadata.id, 7);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries, request(7, "example.com.").queries);
    }

    #[tokio::test]
    async fn request_without_question_is_formerr() {
        let handler = handler(FakeUpstream::default());
        let empty = Message::new(7, MessageType::Query, OpCode::Query);

        let response = handler.handle(&empty).await.response;

        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(handler.upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn request_with_several_questions_is_formerr() {
        let handler = handler(FakeUpstream::default());
        let mut msg = request(7, "a.example.");
        msg.add_query(Query::query(
            Name::from_ascii("b.example.").unwrap(),
            RecordType::A,
        ));

        let response = handler.handle(&msg).await.response;

        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn non_query_opcode_is_notimp() {
        let handler = handler(FakeUpstream::default());
        let mut msg = request(7, "example.com.");
        msg.metadata.op_code = OpCode::Update;

        let response = handler.handle(&msg).await.response;

        assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(response.metadata.op_code, OpCode::Update);
    }

    // RFC 6891 section 7: a responder must include OPT when the request had one.
    #[tokio::test]
    async fn edns_request_gets_edns_response() {
        let handler = handler(FakeUpstream::default());
        let mut msg = request(7, "example.com.");
        msg.set_edns(Edns::new());

        let response = handler.handle(&msg).await.response;

        let edns = response.edns.expect("OPT record in response");
        assert_eq!(edns.max_payload(), EDNS_PAYLOAD);
    }

    #[tokio::test]
    async fn plain_request_gets_no_edns() {
        let handler = handler(FakeUpstream::default());

        let response = handler.handle(&request(7, "example.com.")).await.response;

        assert!(response.edns.is_none());
    }
}
