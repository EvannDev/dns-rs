//! One log line per answered query, under the `dns_rs::query` target so it
//! can be turned off on its own (`RUST_LOG=info,dns_rs::query=off`).

use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};

use crate::handler::Source;

/// The tracing target of query log events.
pub const TARGET: &str = "dns_rs::query";

/// Logs `request` from `client`, answered by `response` in `elapsed`.
pub fn record(
    client: IpAddr,
    request: &Message,
    response: &Message,
    source: Source,
    elapsed: Duration,
) {
    let question = request.queries.first();
    let name = question.map_or_else(|| "-".to_owned(), |q| q.name().to_string());
    let record_type = question.map_or_else(|| "-".to_owned(), |q| q.query_type().to_string());
    tracing::info!(
        target: TARGET,
        %client,
        %name,
        r#type = %record_type,
        rcode = %rcode_name(response.metadata.response_code),
        %source,
        duration_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
    );
}

/// The conventional upper-case name of a response code (`NXDOMAIN`…).
#[must_use]
pub fn rcode_name(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".to_owned(),
        ResponseCode::FormErr => "FORMERR".to_owned(),
        ResponseCode::ServFail => "SERVFAIL".to_owned(),
        ResponseCode::NXDomain => "NXDOMAIN".to_owned(),
        ResponseCode::NotImp => "NOTIMP".to_owned(),
        ResponseCode::Refused => "REFUSED".to_owned(),
        other => format!("RCODE{}", u16::from(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tracing_subscriber::EnvFilter;

    use super::*;

    /// Collects everything the subscriber writes.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn logged(filter: &str, emit: impl FnOnce()) -> String {
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
    }

    fn request() -> Message {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("ads.example.com.").unwrap(),
            RecordType::AAAA,
        ));
        msg
    }

    fn record_example() {
        let response = Message::error_msg(7, OpCode::Query, ResponseCode::NXDomain);
        record(
            "192.168.1.12".parse().unwrap(),
            &request(),
            &response,
            Source::Blocked,
            Duration::from_micros(42),
        );
    }

    #[test]
    fn line_describes_the_query_and_its_outcome() {
        let line = logged("info", record_example);

        for expected in [
            "client=192.168.1.12",
            "name=ads.example.com.",
            "type=AAAA",
            "rcode=NXDOMAIN",
            "source=blocked",
            "duration_us=42",
        ] {
            assert!(
                line.contains(expected),
                "{expected:?} missing from {line:?}"
            );
        }
    }

    #[test]
    fn uses_the_dedicated_target() {
        let line = logged("info", record_example);

        assert!(line.contains(TARGET), "{line:?}");
    }

    #[test]
    fn can_be_turned_off_on_its_own() {
        let line = logged("info,dns_rs::query=off", record_example);

        assert_eq!(line, "");
    }

    #[test]
    fn request_without_question_is_logged_with_placeholders() {
        let empty = Message::new(7, MessageType::Query, OpCode::Query);
        let line = logged("info", || {
            record(
                "10.0.0.1".parse().unwrap(),
                &empty,
                &Message::error_msg(7, OpCode::Query, ResponseCode::FormErr),
                Source::Rejected,
                Duration::ZERO,
            );
        });

        assert!(line.contains("name=-"), "{line:?}");
        assert!(line.contains("type=-"), "{line:?}");
    }

    #[test]
    fn rcode_names_follow_dns_conventions() {
        assert_eq!(rcode_name(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_name(ResponseCode::FormErr), "FORMERR");
        assert_eq!(rcode_name(ResponseCode::ServFail), "SERVFAIL");
        assert_eq!(rcode_name(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_name(ResponseCode::NotImp), "NOTIMP");
        assert_eq!(rcode_name(ResponseCode::Refused), "REFUSED");
        assert_eq!(rcode_name(ResponseCode::BADCOOKIE), "RCODE23");
    }
}
