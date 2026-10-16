//! End to end: a real client talks to dns-rs, which forwards to a fake upstream.

mod common;

use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

use common::{ANSWER, query, start_server, udp_exchange};
use dns_rs::wire::{read_tcp_message, write_tcp_message};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use tokio::net::TcpStream;

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
