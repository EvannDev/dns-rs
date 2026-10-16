//! In-memory cache of upstream DNS responses, keyed by question.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, LowerName, RData, RecordType};

/// Identifies a cached response: the question, compared case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    name: LowerName,
    record_type: RecordType,
    dns_class: DNSClass,
}

impl From<&Query> for CacheKey {
    fn from(query: &Query) -> Self {
        Self {
            name: LowerName::new(query.name()),
            record_type: query.query_type(),
            dns_class: query.query_class(),
        }
    }
}

#[derive(Debug)]
struct Entry {
    response: Message,
    inserted_at: Instant,
    expires_at: Instant,
}

/// Response cache honouring record TTLs.
///
/// Time is passed explicitly so behaviour is deterministic under test.
#[derive(Debug)]
pub struct DnsCache {
    entries: Mutex<HashMap<CacheKey, Entry>>,
    max_entries: usize,
}

impl DnsCache {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Stores `response` if it is cacheable, for as long as its TTL allows.
    ///
    /// When the cache is full, expired entries are purged; if it is still
    /// full, the response is dropped rather than evicting a live entry.
    pub fn insert(&self, key: CacheKey, response: &Message, now: Instant) {
        let Some(ttl) = cacheable_ttl(response) else {
            return;
        };
        let mut entries = self.lock();
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.expires_at > now);
            if entries.len() >= self.max_entries {
                return;
            }
        }
        entries.insert(
            key,
            Entry {
                response: response.clone(),
                inserted_at: now,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Returns the cached response with TTLs reduced by the time spent in cache.
    #[must_use]
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<Message> {
        let mut entries = self.lock();
        let entry = entries.get(key)?;
        if entry.expires_at <= now {
            entries.remove(key);
            return None;
        }
        let elapsed =
            u32::try_from(now.duration_since(entry.inserted_at).as_secs()).unwrap_or(u32::MAX);
        let mut response = entry.response.clone();
        for record in response
            .answers
            .iter_mut()
            .chain(response.authorities.iter_mut())
            .chain(response.additionals.iter_mut())
        {
            record.decrement_ttl(elapsed);
        }
        Some(response)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
        // A panic while holding the lock cannot leave the map inconsistent,
        // so recovering from poisoning is safe.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How long `response` may be cached, or `None` if it must not be.
fn cacheable_ttl(response: &Message) -> Option<u32> {
    if response.metadata.truncation {
        return None;
    }
    let ttl = match response.metadata.response_code {
        ResponseCode::NoError if !response.answers.is_empty() => {
            response.answers.iter().map(|record| record.ttl).min()
        }
        ResponseCode::NoError | ResponseCode::NXDomain => negative_ttl(response),
        _ => None,
    }?;
    (ttl > 0).then_some(ttl)
}

/// Negative caching TTL from the authority SOA (RFC 2308 section 5).
fn negative_ttl(response: &Message) -> Option<u32> {
    response
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use hickory_proto::op::{OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RData, Record};

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn key(s: &str) -> CacheKey {
        CacheKey::from(&Query::query(name(s), RecordType::A))
    }

    fn answer(domain: &str, ttl: u32) -> Message {
        let mut msg = Message::response(42, OpCode::Query);
        msg.add_query(Query::query(name(domain), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name(domain),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        msg
    }

    fn nxdomain(domain: &str, soa_ttl: u32, soa_minimum: u32) -> Message {
        let mut msg = Message::error_msg(42, OpCode::Query, ResponseCode::NXDomain);
        msg.add_query(Query::query(name(domain), RecordType::A));
        let soa = SOA::new(
            name("ns.example."),
            name("admin.example."),
            1,
            3600,
            600,
            86400,
            soa_minimum,
        );
        msg.authorities.push(Record::from_rdata(
            name("example."),
            soa_ttl,
            RData::SOA(soa),
        ));
        msg
    }

    #[test]
    fn miss_on_empty_cache() {
        let cache = DnsCache::new(10);
        assert!(cache.get(&key("example.com."), Instant::now()).is_none());
    }

    #[test]
    fn hit_returns_cached_answers() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        cache.insert(key("example.com."), &answer("example.com.", 300), now);

        let hit = cache.get(&key("example.com."), now).expect("cache hit");
        assert_eq!(hit.answers, answer("example.com.", 300).answers);
    }

    #[test]
    fn key_is_case_insensitive() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        cache.insert(key("Example.COM."), &answer("example.com.", 300), now);

        assert!(cache.get(&key("example.com."), now).is_some());
    }

    #[test]
    fn key_distinguishes_record_types() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        cache.insert(key("example.com."), &answer("example.com.", 300), now);

        let aaaa = CacheKey::from(&Query::query(name("example.com."), RecordType::AAAA));
        assert!(cache.get(&aaaa, now).is_none());
    }

    #[test]
    fn ttl_decreases_with_elapsed_time() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        cache.insert(key("example.com."), &answer("example.com.", 300), now);

        let hit = cache
            .get(&key("example.com."), now + Duration::from_secs(100))
            .unwrap();
        assert_eq!(hit.answers[0].ttl, 200);
    }

    #[test]
    fn entry_expires_after_lowest_ttl() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        let mut msg = answer("example.com.", 300);
        msg.answers.push(Record::from_rdata(
            name("example.com."),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));
        cache.insert(key("example.com."), &msg, now);

        let later = now + Duration::from_secs(60);
        assert!(cache.get(&key("example.com."), later).is_none());
    }

    #[test]
    fn zero_ttl_is_not_cached() {
        let cache = DnsCache::new(10);
        cache.insert(
            key("example.com."),
            &answer("example.com.", 0),
            Instant::now(),
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn server_failure_is_not_cached() {
        let cache = DnsCache::new(10);
        let msg = Message::error_msg(42, OpCode::Query, ResponseCode::ServFail);
        cache.insert(key("example.com."), &msg, Instant::now());
        assert!(cache.is_empty());
    }

    #[test]
    fn truncated_response_is_not_cached() {
        let cache = DnsCache::new(10);
        let mut msg = answer("example.com.", 300);
        msg.metadata.truncation = true;
        cache.insert(key("example.com."), &msg, Instant::now());
        assert!(cache.is_empty());
    }

    // RFC 2308 section 5: negative answers live for min(SOA TTL, SOA MINIMUM).
    #[test]
    fn nxdomain_is_cached_for_soa_negative_ttl() {
        let cache = DnsCache::new(10);
        let now = Instant::now();
        cache.insert(
            key("nope.example."),
            &nxdomain("nope.example.", 3600, 120),
            now,
        );

        let still = cache.get(&key("nope.example."), now + Duration::from_secs(119));
        assert_eq!(
            still.unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
        assert!(
            cache
                .get(&key("nope.example."), now + Duration::from_secs(120))
                .is_none()
        );
    }

    #[test]
    fn negative_answer_without_soa_is_not_cached() {
        let cache = DnsCache::new(10);
        let msg = Message::error_msg(42, OpCode::Query, ResponseCode::NXDomain);
        cache.insert(key("nope.example."), &msg, Instant::now());
        assert!(cache.is_empty());
    }

    #[test]
    fn full_cache_evicts_expired_entries_first() {
        let cache = DnsCache::new(2);
        let now = Instant::now();
        cache.insert(key("a.example."), &answer("a.example.", 10), now);
        cache.insert(key("b.example."), &answer("b.example.", 300), now);

        let later = now + Duration::from_secs(20);
        cache.insert(key("c.example."), &answer("c.example.", 300), later);

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key("b.example."), later).is_some());
        assert!(cache.get(&key("c.example."), later).is_some());
    }

    #[test]
    fn full_cache_with_live_entries_never_exceeds_capacity() {
        let cache = DnsCache::new(2);
        let now = Instant::now();
        for domain in ["a.example.", "b.example.", "c.example."] {
            cache.insert(key(domain), &answer(domain, 300), now);
        }
        assert_eq!(cache.len(), 2);
    }
}
