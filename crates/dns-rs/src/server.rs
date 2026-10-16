//! UDP and TCP listeners feeding requests to the [`Handler`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::handler::Handler;
use crate::upstream::Upstream;
use crate::wire::{read_tcp_message, write_tcp_message};

/// Closes TCP connections idle for this long (RFC 7766 recommends seconds).
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

const HEADER_LEN: usize = 12;

/// UDP payload every client accepts (RFC 1035 section 2.3.4).
const MIN_UDP_PAYLOAD: u16 = 512;

/// Serves DNS over UDP until the socket fails.
pub async fn serve_udp<U: Upstream>(socket: UdpSocket, handler: Arc<Handler<U>>) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0; usize::from(u16::MAX)];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let datagram = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let Some((response, max_payload)) = respond(&handler, &datagram, peer).await else {
                return;
            };
            let bytes = udp_response_bytes(&response, max_payload);
            if let Err(error) = socket.send_to(&bytes, peer).await {
                tracing::debug!(%peer, %error, "failed to send UDP response");
            }
        });
    }
}

/// Serves DNS over TCP until the listener fails.
pub async fn serve_tcp<U: Upstream>(
    listener: TcpListener,
    handler: Arc<Handler<U>>,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(error) = serve_tcp_connection(stream, peer, &handler).await {
                tracing::debug!(%peer, %error, "TCP connection closed");
            }
        });
    }
}

/// Answers queries on one connection, in order, until the client goes idle.
async fn serve_tcp_connection<U: Upstream>(
    mut stream: TcpStream,
    peer: SocketAddr,
    handler: &Handler<U>,
) -> io::Result<()> {
    loop {
        let Ok(message) = timeout(TCP_IDLE_TIMEOUT, read_tcp_message(&mut stream)).await else {
            return Ok(());
        };
        let message = match message {
            Ok(message) => message,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        if let Some((response, _)) = respond(handler, &message, peer).await {
            write_tcp_message(&mut stream, &encode(&response)).await?;
        }
    }
}

/// Decodes `bytes` and computes the response, if one is due, along with the
/// largest UDP payload the client accepts.
async fn respond<U: Upstream>(
    handler: &Handler<U>,
    bytes: &[u8],
    peer: SocketAddr,
) -> Option<(Message, u16)> {
    match Message::from_vec(bytes) {
        Ok(request) if request.metadata.message_type == MessageType::Response => {
            tracing::debug!(%peer, "ignoring a DNS response sent as a query");
            None
        }
        Ok(request) => Some((handler.handle(&request).await, request.max_payload())),
        Err(error) => {
            tracing::debug!(%peer, %error, "malformed query");
            formerr_from_header(bytes).map(|response| (response, MIN_UDP_PAYLOAD))
        }
    }
}

/// A FORMERR for an undecodable query, if at least its header is readable
/// and it claims to be a query.
fn formerr_from_header(bytes: &[u8]) -> Option<Message> {
    if bytes.len() < HEADER_LEN || bytes[2] & 0x80 != 0 {
        return None;
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    Some(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr))
}

/// Serializes `response` for UDP, truncating it if it exceeds `max_payload`
/// (512 bytes, or the client's EDNS payload size).
#[must_use]
pub fn udp_response_bytes(response: &Message, max_payload: u16) -> Vec<u8> {
    let bytes = encode(response);
    if bytes.len() <= usize::from(max_payload) {
        bytes
    } else {
        encode(&response.truncate())
    }
}

fn encode(message: &Message) -> Vec<u8> {
    message.to_vec().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to encode response");
        encode_servfail(message.metadata.id)
    })
}

fn encode_servfail(id: u16) -> Vec<u8> {
    Message::error_msg(id, OpCode::Query, ResponseCode::ServFail)
        .to_vec()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{Edns, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;

    fn request(edns_payload: Option<u16>) -> Message {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("big.example.").unwrap(),
            RecordType::A,
        ));
        if let Some(payload) = edns_payload {
            let mut edns = Edns::new();
            edns.set_max_payload(payload);
            msg.set_edns(edns);
        }
        msg
    }

    fn response_with(records: u8) -> Message {
        let mut msg = Message::response(7, OpCode::Query);
        msg.add_queries(request(None).queries);
        for i in 0..records {
            msg.add_answer(Record::from_rdata(
                Name::from_ascii("big.example.").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, i))),
            ));
        }
        msg
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    #[test]
    fn small_response_is_sent_whole() {
        let bytes = udp_response_bytes(&response_with(2), request(None).max_payload());

        let sent = decode(&bytes);
        assert!(!sent.metadata.truncation);
        assert_eq!(sent.answers.len(), 2);
    }

    #[test]
    fn response_over_512_bytes_is_truncated_without_edns() {
        let bytes = udp_response_bytes(&response_with(40), request(None).max_payload());

        assert!(bytes.len() <= 512);
        let sent = decode(&bytes);
        assert!(sent.metadata.truncation);
        assert_eq!(sent.metadata.id, 7);
        assert_eq!(sent.answers, []);
    }

    #[test]
    fn edns_payload_size_raises_the_limit() {
        let bytes = udp_response_bytes(&response_with(40), request(Some(1232)).max_payload());

        let sent = decode(&bytes);
        assert!(!sent.metadata.truncation);
        assert_eq!(sent.answers.len(), 40);
    }
}
