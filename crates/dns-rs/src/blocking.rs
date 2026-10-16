//! What to answer for a blocked domain.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

use crate::filter::Filter;

/// TTL of synthesized answers: short, so unblocking takes effect quickly.
pub const BLOCKED_TTL: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockingMode {
    /// `0.0.0.0` / `::` for A / AAAA, empty NOERROR otherwise (Pi-hole default).
    #[default]
    Null,
    NxDomain,
    /// Empty NOERROR for every type.
    NoData,
    Refused,
}

/// The rules in force: which domains are blocked, and how.
#[derive(Debug)]
pub struct Policy {
    pub filter: Filter,
    pub mode: BlockingMode,
}

impl Policy {
    /// A policy that blocks nothing.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            filter: Filter::empty(),
            mode: BlockingMode::default(),
        }
    }
}

/// The response code and answers for `question`, which is blocked.
#[must_use]
pub fn blocked_answer(question: &Query, mode: BlockingMode) -> (ResponseCode, Vec<Record>) {
    match mode {
        BlockingMode::Null => {
            let data = match question.query_type() {
                RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
                RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
                _ => None,
            };
            let answers = data
                .map(|data| Record::from_rdata(question.name().clone(), BLOCKED_TTL, data))
                .into_iter()
                .collect();
            (ResponseCode::NoError, answers)
        }
        BlockingMode::NxDomain => (ResponseCode::NXDomain, Vec::new()),
        BlockingMode::NoData => (ResponseCode::NoError, Vec::new()),
        BlockingMode::Refused => (ResponseCode::Refused, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, RecordType};

    use super::*;

    fn question(record_type: RecordType) -> Query {
        Query::query(Name::from_ascii("ads.example.com.").unwrap(), record_type)
    }

    #[test]
    fn null_mode_answers_a_with_unspecified_ipv4() {
        let (code, answers) = blocked_answer(&question(RecordType::A), BlockingMode::Null);

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(
            answers,
            vec![Record::from_rdata(
                Name::from_ascii("ads.example.com.").unwrap(),
                BLOCKED_TTL,
                RData::A(A(Ipv4Addr::UNSPECIFIED)),
            )]
        );
    }

    #[test]
    fn null_mode_answers_aaaa_with_unspecified_ipv6() {
        let (code, answers) = blocked_answer(&question(RecordType::AAAA), BlockingMode::Null);

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    }

    // HTTPS/SVCB records can carry address hints: answering them normally
    // would let browsers bypass the block.
    #[test]
    fn null_mode_answers_other_types_with_nodata() {
        for record_type in [RecordType::HTTPS, RecordType::MX, RecordType::TXT] {
            let (code, answers) = blocked_answer(&question(record_type), BlockingMode::Null);

            assert_eq!(code, ResponseCode::NoError, "{record_type}");
            assert_eq!(answers, [], "{record_type}");
        }
    }

    #[test]
    fn nxdomain_mode_says_the_name_does_not_exist() {
        let (code, answers) = blocked_answer(&question(RecordType::A), BlockingMode::NxDomain);

        assert_eq!(code, ResponseCode::NXDomain);
        assert_eq!(answers, []);
    }

    #[test]
    fn nodata_mode_answers_empty_noerror() {
        let (code, answers) = blocked_answer(&question(RecordType::A), BlockingMode::NoData);

        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(answers, []);
    }

    #[test]
    fn refused_mode_refuses() {
        let (code, answers) = blocked_answer(&question(RecordType::AAAA), BlockingMode::Refused);

        assert_eq!(code, ResponseCode::Refused);
        assert_eq!(answers, []);
    }
}
