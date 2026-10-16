//! DNS over TCP framing (RFC 1035 section 4.2.2): a 2-byte length prefix.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads one length-prefixed DNS message.
pub async fn read_tcp_message<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u16().await?;
    let mut message = vec![0; usize::from(len)];
    reader.read_exact(&mut message).await?;
    Ok(message)
}

/// Writes one length-prefixed DNS message.
pub async fn write_tcp_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> io::Result<()> {
    let len = u16::try_from(message.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS message exceeds 65535 bytes",
        )
    })?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    writer.write_all(&frame).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_message() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        write_tcp_message(&mut client, b"hello").await.unwrap();

        assert_eq!(read_tcp_message(&mut server).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn prefixes_message_with_big_endian_length() {
        let mut buffer = Vec::new();

        write_tcp_message(&mut buffer, &[0xAB; 258]).await.unwrap();

        assert_eq!(&buffer[..2], &[0x01, 0x02]);
        assert_eq!(buffer.len(), 260);
    }

    #[tokio::test]
    async fn rejects_message_longer_than_u16() {
        let mut buffer = Vec::new();

        let error = write_tcp_message(&mut buffer, &vec![0; 70_000])
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn truncated_stream_is_an_error() {
        let mut stream: &[u8] = &[0x00, 0x05, b'a', b'b'];

        let error = read_tcp_message(&mut stream).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
