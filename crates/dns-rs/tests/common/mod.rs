//! Shared harness: a dns-rs server wired to a fake upstream on loopback.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_rs::blocking::Policy;
use dns_rs::cache::DnsCache;
use dns_rs::handler::Handler;
use dns_rs::metrics::Metrics;
use dns_rs::server::{serve_tcp, serve_udp};
use dns_rs::upstream::DnsUpstream;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

pub const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// Fake upstream answering every A query with [`ANSWER`]; counts queries.
async fn fake_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&buf[..len]).unwrap();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.add_queries(request.queries.iter().cloned());
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                300,
                RData::A(A(ANSWER)),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (addr, calls)
}

pub struct TestServer {
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub upstream_calls: Arc<AtomicUsize>,
    pub metrics: Arc<Metrics>,
}

pub async fn start_server() -> TestServer {
    start_server_with_policy(Policy::allow_all()).await
}

pub async fn start_server_with_policy(policy: Policy) -> TestServer {
    let (upstream_addr, upstream_calls) = fake_upstream().await;
    let upstream = DnsUpstream::new(upstream_addr, Duration::from_secs(1));
    let handler = Arc::new(Handler::new(upstream, DnsCache::new(100)));
    handler.set_policy(policy);

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = TestServer {
        udp: udp_socket.local_addr().unwrap(),
        tcp: tcp_listener.local_addr().unwrap(),
        upstream_calls,
        metrics: Arc::new(Metrics::new()),
    };
    tokio::spawn(serve_udp(
        udp_socket,
        Arc::clone(&handler),
        Arc::clone(&server.metrics),
    ));
    tokio::spawn(serve_tcp(
        tcp_listener,
        handler,
        Arc::clone(&server.metrics),
    ));
    server
}

pub fn query(id: u16, domain: &str) -> Message {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    msg
}

pub async fn udp_exchange(server: SocketAddr, payload: &[u8]) -> Option<Message> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(payload, server).await.unwrap();
    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_millis(500), client.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buf[..len]).unwrap())
}

/// Collects everything a tracing subscriber writes.
#[derive(Clone, Default)]
pub struct Capture(pub Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
