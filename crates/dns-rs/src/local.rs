//! Records the operator gives an address to, answered by dns-rs itself
//! (ADR 0016).

use std::collections::HashMap;
use std::net::IpAddr;

use hickory_proto::op::Query;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

/// TTL of local answers when the configuration sets none.
pub const DEFAULT_TTL: u32 = 300;

/// Addresses by name. Names are compared without case or trailing dot.
#[derive(Debug, Default)]
pub struct LocalRecords {
    ttl: u32,
    by_name: HashMap<String, Vec<IpAddr>>,
}

impl LocalRecords {
    /// Records from `(name, address)` pairs; a pair given twice counts once.
    pub fn new<'a>(records: impl IntoIterator<Item = (&'a str, IpAddr)>, ttl: u32) -> Self {
        let mut by_name: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for (name, ip) in records {
            let addresses = by_name.entry(key(name)).or_default();
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        Self { ttl, by_name }
    }

    /// Number of local names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The answers to `question` if its name is local, `None` otherwise. A
    /// local name always exists: a type without records gets no answers,
    /// to be sent as an empty NOERROR.
    #[must_use]
    pub fn answer(&self, question: &Query) -> Option<Vec<Record>> {
        let addresses = self.by_name.get(&key(&question.name().to_ascii()))?;
        let wanted = question.query_type();
        Some(
            addresses
                .iter()
                .filter_map(|ip| match (ip, wanted) {
                    (IpAddr::V4(ip), RecordType::A | RecordType::ANY) => Some(RData::A(A(*ip))),
                    (IpAddr::V6(ip), RecordType::AAAA | RecordType::ANY) => {
                        Some(RData::AAAA(AAAA(*ip)))
                    }
                    _ => None,
                })
                .map(|data| Record::from_rdata(question.name().clone(), self.ttl, data))
                .collect(),
        )
    }
}

/// `name` without case or trailing dot.
fn key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::rr::Name;

    use super::*;

    const NAS_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    const NAS_V4_BIS: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
    const NAS_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x10));

    fn records() -> LocalRecords {
        LocalRecords::new(
            [
                ("nas.home.arpa", NAS_V4),
                ("nas.home.arpa", NAS_V4_BIS),
                ("nas.home.arpa", NAS_V6),
                ("printer.home.arpa", NAS_V4_BIS),
            ],
            DEFAULT_TTL,
        )
    }

    fn question(name: &str, record_type: RecordType) -> Query {
        Query::query(Name::from_ascii(name).unwrap(), record_type)
    }

    fn data(answers: &[Record]) -> Vec<RData> {
        answers.iter().map(|record| record.data.clone()).collect()
    }

    #[test]
    fn a_query_gets_the_ipv4_addresses_of_a_local_name() {
        let answers = records()
            .answer(&question("nas.home.arpa.", RecordType::A))
            .unwrap();

        assert_eq!(
            data(&answers),
            [
                RData::A(A(Ipv4Addr::new(192, 168, 1, 10))),
                RData::A(A(Ipv4Addr::new(192, 168, 1, 11)))
            ]
        );
        assert!(answers.iter().all(|record| record.ttl == DEFAULT_TTL));
    }

    #[test]
    fn aaaa_query_gets_the_ipv6_addresses() {
        let answers = records()
            .answer(&question("nas.home.arpa.", RecordType::AAAA))
            .unwrap();

        assert_eq!(
            data(&answers),
            [RData::AAAA(AAAA(Ipv6Addr::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 0x10
            )))]
        );
    }

    #[test]
    fn any_query_gets_every_address() {
        let answers = records()
            .answer(&question("nas.home.arpa.", RecordType::ANY))
            .unwrap();

        assert_eq!(answers.len(), 3);
    }

    // RFC 4343: names compare without case. The answer keeps the name as
    // the client wrote it, as resolvers checking 0x20 randomization expect.
    #[test]
    fn names_match_without_case_and_answers_keep_the_question_name() {
        let answers = records()
            .answer(&question("NaS.Home.ARPA.", RecordType::A))
            .unwrap();

        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].name.to_ascii(), "NaS.Home.ARPA.");
    }

    #[test]
    fn configured_names_match_with_or_without_case_and_trailing_dot() {
        let records = LocalRecords::new([("Router.Home.Arpa.", NAS_V4)], 60);

        let answers = records
            .answer(&question("router.home.arpa.", RecordType::A))
            .unwrap();

        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].ttl, 60);
    }

    // The name exists: other types get an empty NOERROR, not NXDOMAIN.
    #[test]
    fn other_types_of_a_local_name_get_no_answers() {
        for record_type in [RecordType::MX, RecordType::TXT] {
            let answers = records().answer(&question("nas.home.arpa.", record_type));

            assert_eq!(answers.map(|a| a.len()), Some(0), "{record_type}");
        }
    }

    #[test]
    fn family_without_records_gets_no_answers() {
        let answers = records().answer(&question("printer.home.arpa.", RecordType::AAAA));

        assert_eq!(answers.map(|a| a.len()), Some(0));
    }

    #[test]
    fn subdomains_of_a_local_name_are_not_local() {
        assert!(
            records()
                .answer(&question("x.nas.home.arpa.", RecordType::A))
                .is_none()
        );
    }

    #[test]
    fn unknown_names_are_not_local() {
        assert!(
            records()
                .answer(&question("example.com.", RecordType::A))
                .is_none()
        );
    }

    #[test]
    fn a_record_given_twice_is_answered_once() {
        let records =
            LocalRecords::new([("nas.home.arpa", NAS_V4), ("NAS.home.arpa.", NAS_V4)], 60);

        let answers = records
            .answer(&question("nas.home.arpa.", RecordType::A))
            .unwrap();

        assert_eq!(answers.len(), 1);
        assert_eq!(records.len(), 1);
    }
}
