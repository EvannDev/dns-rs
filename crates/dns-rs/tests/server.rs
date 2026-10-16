//! End to end: a real client talks to dns-rs, which forwards to a fake upstream.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_rs::cache::DnsCache;
use dns_rs::handler::Handler;
use dns_rs::server::{serve_tcp, serve_udp};
use dns_rs::upstream::DnsUpstream;
use dns_rs::wire::{read_tcp_message, write_tcp_message};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

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

struct TestServer {
    udp: SocketAddr,
    tcp: SocketAddr,
    upstream_calls: Arc<AtomicUsize>,
}

async fn start_server() -> TestServer {
    let (upstream_addr, upstream_calls) = fake_upstream().await;
    let upstream = DnsUpstream::new(upstream_addr, Duration::from_secs(1));
    let handler = Arc::new(Handler::new(upstream, DnsCache::new(100)));

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = TestServer {
        udp: udp_socket.local_addr().unwrap(),
        tcp: tcp_listener.local_addr().unwrap(),
        upstream_calls,
    };
    tokio::spawn(serve_udp(udp_socket, Arc::clone(&handler)));
    tokio::spawn(serve_tcp(tcp_listener, handler));
    server
}

fn query(id: u16, domain: &str) -> Message {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    msg
}

async fn udp_exchange(server: SocketAddr, payload: &[u8]) -> Option<Message> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(payload, server).await.unwrap();
    let mut buf = [0u8; 4096];
    let len = timeout(Duration::from_millis(500), client.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buf[..len]).unwrap())
}

fn first_a(response: &Message) -> Ipv4Addr {
    match response.answers[0].data {
        RData::A(A(ip)) => ip,
        ref other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn answers_over_udp() {
    let server = start_server().await;

    let response = udp_exchange(server.udp, &query(7, "example.com.").to_vec().unwrap())
        .await
        .expect("a response");

    assert_eq!(response.metadata.id, 7);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_a(&response), ANSWER);
}

#[tokio::test]
async fn answers_pipelined_queries_over_one_tcp_connection() {
    let server = start_server().await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();

    for id in [1, 2] {
        write_tcp_message(&mut stream, &query(id, "example.com.").to_vec().unwrap())
            .await
            .unwrap();
    }
    for id in [1, 2] {
        let bytes = read_tcp_message(&mut stream).await.unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert_eq!(response.metadata.id, id);
        assert_eq!(first_a(&response), ANSWER);
    }
}

#[tokio::test]
async fn caches_across_transports() {
    let server = start_server().await;

    udp_exchange(server.udp, &query(1, "example.com.").to_vec().unwrap()).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    write_tcp_message(&mut stream, &query(2, "example.com.").to_vec().unwrap())
        .await
        .unwrap();
    read_tcp_message(&mut stream).await.unwrap();

    assert_eq!(server.upstream_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keeps_serving_after_a_malformed_datagram() {
    let server = start_server().await;

    udp_exchange(server.udp, b"\x00\x01garbage").await;
    let response = udp_exchange(server.udp, &query(7, "example.com.").to_vec().unwrap()).await;

    assert!(response.is_some());
}

#[tokio::test]
async fn malformed_query_with_a_header_gets_formerr() {
    let server = start_server().await;
    // A valid header announcing one question, but no question follows.
    let header = [0x00, 0x2A, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    let response = udp_exchange(server.udp, &header).await.expect("a response");

    assert_eq!(response.metadata.id, 0x2A);
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
}

// Answering responses would let two servers bounce packets forever.
#[tokio::test]
async fn ignores_datagrams_that_are_responses() {
    let server = start_server().await;
    let mut msg = query(7, "example.com.");
    msg.metadata.message_type = MessageType::Response;

    let response = udp_exchange(server.udp, &msg.to_vec().unwrap()).await;

    assert!(response.is_none());
}
