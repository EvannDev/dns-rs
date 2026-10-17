//! Forwarding of queries to upstream resolvers.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};

use crate::cache::CacheKey;
use crate::wire::{read_tcp_message, write_tcp_message};

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream did not answer in time")]
    Timeout,
    #[error("upstream I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid DNS message: {0}")]
    Proto(String),
    #[error("upstream response does not match the query")]
    Mismatch,
}

/// A resolver that queries are forwarded to.
pub trait Upstream: Send + Sync + 'static {
    /// Sends `query` and returns the upstream response.
    fn query(&self, query: &Message)
    -> impl Future<Output = Result<Message, UpstreamError>> + Send;
}

/// An upstream built from an address, as the servers of forwarded domains
/// are on each reload (ADR 0017).
pub trait Connect: Upstream + Sized {
    fn connect(addr: SocketAddr, timeout: Duration) -> Self;
}

/// A classic DNS server reached over UDP, falling back to TCP on truncation.
#[derive(Debug, Clone)]
pub struct DnsUpstream {
    addr: SocketAddr,
    timeout: Duration,
}

impl DnsUpstream {
    #[must_use]
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}

impl Connect for DnsUpstream {
    fn connect(addr: SocketAddr, timeout: Duration) -> Self {
        Self::new(addr, timeout)
    }
}

impl Upstream for DnsUpstream {
    async fn query(&self, query: &Message) -> Result<Message, UpstreamError> {
        let request = query
            .to_vec()
            .map_err(|e| UpstreamError::Proto(e.to_string()))?;
        let deadline = Instant::now() + self.timeout;

        let response = timeout_at(deadline, self.query_udp(query, &request))
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        if !response.metadata.truncation {
            return Ok(response);
        }

        tracing::debug!(upstream = %self.addr, "truncated UDP response, retrying over TCP");
        timeout_at(deadline, self.query_tcp(query, &request))
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

impl DnsUpstream {
    /// Waits for the first datagram that answers `query`, ignoring any other.
    async fn query_udp(&self, query: &Message, request: &[u8]) -> Result<Message, UpstreamError> {
        let local: SocketAddr = if self.addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local).await?;
        // Connecting makes the kernel drop datagrams from any other source.
        socket.connect(self.addr).await?;
        socket.send(request).await?;

        let mut buf = vec![0; usize::from(u16::MAX)];
        loop {
            let len = socket.recv(&mut buf).await?;
            match Message::from_vec(&buf[..len]) {
                Ok(response) if answers(query, &response) => return Ok(response),
                Ok(_) => tracing::debug!(upstream = %self.addr, "ignoring mismatched response"),
                Err(error) => {
                    tracing::debug!(upstream = %self.addr, %error, "ignoring malformed response");
                }
            }
        }
    }

    async fn query_tcp(&self, query: &Message, request: &[u8]) -> Result<Message, UpstreamError> {
        let mut stream = TcpStream::connect(self.addr).await?;
        write_tcp_message(&mut stream, request).await?;
        let bytes = read_tcp_message(&mut stream).await?;
        let response =
            Message::from_vec(&bytes).map_err(|e| UpstreamError::Proto(e.to_string()))?;
        if answers(query, &response) {
            Ok(response)
        } else {
            Err(UpstreamError::Mismatch)
        }
    }
}

/// Whether `response` is the answer to `query`: same ID and same question.
fn answers(query: &Message, response: &Message) -> bool {
    response.metadata.id == query.metadata.id
        && response.queries.len() == query.queries.len()
        && response
            .queries
            .iter()
            .zip(&query.queries)
            .all(|(a, b)| CacheKey::from(a) == CacheKey::from(b))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    use crate::wire::{read_tcp_message, write_tcp_message};

    const TIMEOUT: Duration = Duration::from_millis(300);

    fn query() -> Message {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn answer_to(query: &Message, last_octet: u8) -> Message {
        let mut msg = Message::response(query.metadata.id, OpCode::Query);
        msg.add_queries(query.queries.iter().cloned());
        msg.add_answer(Record::from_rdata(
            query.queries[0].name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, last_octet))),
        ));
        msg
    }

    /// Binds a UDP socket on localhost and serves each request with `respond`,
    /// which returns the raw datagrams to send back.
    async fn udp_server<F>(respond: F) -> SocketAddr
    where
        F: Fn(&Message) -> Vec<Message> + Send + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_vec(&buf[..len]).unwrap();
                for response in respond(&request) {
                    socket
                        .send_to(&response.to_vec().unwrap(), peer)
                        .await
                        .unwrap();
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn returns_udp_answer() {
        let addr = udp_server(|q| vec![answer_to(q, 1)]).await;
        let upstream = DnsUpstream::new(addr, TIMEOUT);

        let response = upstream.query(&query()).await.unwrap();

        assert_eq!(response.answers, answer_to(&query(), 1).answers);
    }

    #[tokio::test]
    async fn ignores_response_with_wrong_id() {
        let addr = udp_server(|q| {
            let mut spoofed = answer_to(q, 66);
            spoofed.metadata.id = q.metadata.id.wrapping_add(1);
            vec![spoofed, answer_to(q, 1)]
        })
        .await;
        let upstream = DnsUpstream::new(addr, TIMEOUT);

        let response = upstream.query(&query()).await.unwrap();

        assert_eq!(response.answers, answer_to(&query(), 1).answers);
    }

    #[tokio::test]
    async fn ignores_response_with_wrong_question() {
        let addr = udp_server(|q| {
            let mut spoofed = answer_to(q, 66);
            spoofed.queries[0] =
                Query::query(Name::from_ascii("evil.example.").unwrap(), RecordType::A);
            vec![spoofed, answer_to(q, 1)]
        })
        .await;
        let upstream = DnsUpstream::new(addr, TIMEOUT);

        let response = upstream.query(&query()).await.unwrap();

        assert_eq!(response.answers, answer_to(&query(), 1).answers);
    }

    #[tokio::test]
    async fn times_out_when_upstream_is_silent() {
        let addr = udp_server(|_| vec![]).await;
        let upstream = DnsUpstream::new(addr, TIMEOUT);

        let error = upstream.query(&query()).await.unwrap_err();

        assert!(matches!(error, UpstreamError::Timeout), "{error:?}");
    }

    #[tokio::test]
    async fn retries_over_tcp_when_udp_response_is_truncated() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let request = Message::from_vec(&read_tcp_message(&mut stream).await.unwrap()).unwrap();
            let response = answer_to(&request, 2).to_vec().unwrap();
            write_tcp_message(&mut stream, &response).await.unwrap();
        });
        let udp = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let truncated = answer_to(&request, 1).truncate();
            udp.send_to(&truncated.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let upstream = DnsUpstream::new(addr, TIMEOUT);

        let response = upstream.query(&query()).await.unwrap();

        assert!(!response.metadata.truncation);
        assert_eq!(response.answers, answer_to(&query(), 2).answers);
    }
}
