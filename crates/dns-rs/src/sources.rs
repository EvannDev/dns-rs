//! Fetching the blocklists named in the configuration.

use std::time::Duration;

use crate::config::ListSource;
use crate::lists::{ParsedList, parse_list};

/// Downloads give up after this long.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Larger lists are rejected: the biggest public lists are a few dozen MiB.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Loads blocklists from files and HTTP(S) URLs.
#[derive(Debug, Clone)]
pub struct ListLoader {
    timeout: Duration,
    max_bytes: usize,
}

impl Default for ListLoader {
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT, DEFAULT_MAX_BYTES)
    }
}

impl ListLoader {
    #[must_use]
    pub fn new(timeout: Duration, max_bytes: usize) -> Self {
        Self { timeout, max_bytes }
    }

    /// Loads and parses every list, concurrently. A list that cannot be
    /// loaded is logged and skipped: DNS must keep working without it.
    /// Lists come back in the order of `sources`, minus the skipped ones.
    pub async fn load(&self, sources: &[ListSource]) -> Vec<ParsedList> {
        let client = self.client();

        let mut tasks = tokio::task::JoinSet::new();
        for (index, source) in sources.iter().cloned().enumerate() {
            if source.is_insecure() {
                tracing::warn!(list = %source, "blocklist fetched over plain HTTP, prefer HTTPS");
            }
            let client = client.clone();
            let max_bytes = self.max_bytes;
            tasks.spawn(async move {
                let text = match &source {
                    ListSource::File(path) => tokio::fs::read_to_string(path)
                        .await
                        .map_err(|error| error.to_string()),
                    ListSource::Http(url) => match &client {
                        Some(client) => fetch(client, url, max_bytes).await,
                        None => Err("no HTTP client".to_owned()),
                    },
                };
                (index, source, text)
            });
        }

        let mut loaded = Vec::with_capacity(sources.len());
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((index, source, Ok(text))) => {
                    let list = parse_list(&text);
                    tracing::info!(
                        list = %source,
                        deny = list.deny.len(),
                        allow = list.allow.len(),
                        skipped = list.skipped,
                        "blocklist loaded"
                    );
                    loaded.push((index, list));
                }
                Ok((_, source, Err(error))) => {
                    tracing::warn!(list = %source, %error, "cannot load blocklist, skipped");
                }
                Err(error) => tracing::error!(%error, "blocklist task failed"),
            }
        }
        loaded.sort_by_key(|(index, _)| *index);
        loaded.into_iter().map(|(_, list)| list).collect()
    }

    /// The HTTP client, or `None` (logged) if TLS cannot be initialized.
    fn client(&self) -> Option<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .inspect_err(|error| {
                tracing::error!(%error, "cannot create HTTP client, HTTP lists skipped");
            })
            .ok()
    }
}

/// Downloads `url`, refusing bodies over `max_bytes`, whatever the headers say.
async fn fetch(client: &reqwest::Client, url: &str, max_bytes: usize) -> Result<String, String> {
    let too_large = || format!("list larger than {max_bytes} bytes");
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| error.to_string())?;
    if response
        .content_length()
        .is_some_and(|len| len > u64::try_from(max_bytes).unwrap_or(u64::MAX))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len() + chunk.len() > max_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Loads lists with the default limits.
pub async fn load_lists(sources: &[ListSource]) -> Vec<ParsedList> {
    ListLoader::default().load(sources).await
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::filter::Rule;

    fn list_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn loader() -> ListLoader {
        ListLoader::new(Duration::from_millis(500), 1024)
    }

    /// What the test HTTP server sends back.
    #[derive(Clone)]
    enum Reply {
        /// Status and body, with a correct Content-Length.
        Ok(u16, String),
        /// Body without Content-Length, delimited by closing the connection.
        Unsized(String),
        /// A Content-Length header announcing `usize` bytes, and no body.
        Announced(usize),
        /// Never answers.
        Silent,
    }

    /// Serves `reply` to every request on a loopback port.
    async fn http_server(reply: Reply) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let len = stream.read(&mut buf).await.unwrap();
                        if len == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..len]);
                    }
                    let response = match reply {
                        Reply::Ok(status, body) => format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ),
                        Reply::Unsized(body) => {
                            format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}")
                        }
                        Reply::Announced(len) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
                        ),
                        Reply::Silent => {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            return;
                        }
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn http(addr: SocketAddr, path: &str) -> ListSource {
        ListSource::Http(format!("http://{addr}{path}"))
    }

    #[tokio::test]
    async fn file_list_is_read_and_parsed() {
        let file = list_file("0.0.0.0 ads.example.com\n||tracker.example^\n");

        let lists = loader().load(&[ListSource::File(file.path().into())]).await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![
                Rule::Exact("ads.example.com".to_owned()),
                Rule::Subtree("tracker.example".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn unreadable_list_is_skipped() {
        let file = list_file("ads.example.com");

        let lists = loader()
            .load(&[
                ListSource::File("/nonexistent/list.txt".into()),
                ListSource::File(file.path().into()),
            ])
            .await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn http_list_is_downloaded_and_parsed() {
        let addr = http_server(Reply::Ok(200, "0.0.0.0 ads.example.com\n".to_owned())).await;

        let lists = loader().load(&[http(addr, "/hosts")]).await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn error_status_skips_the_list() {
        let addr = http_server(Reply::Ok(404, "ads.example.com".to_owned())).await;

        let lists = loader().load(&[http(addr, "/missing")]).await;

        assert_eq!(lists, []);
    }

    #[tokio::test]
    async fn silent_server_times_out_and_skips_the_list() {
        let addr = http_server(Reply::Silent).await;
        let started = std::time::Instant::now();

        let lists = loader().load(&[http(addr, "/slow")]).await;

        assert_eq!(lists, []);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn unreachable_server_skips_the_list() {
        // Bind then drop: nothing listens on this port any more.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();

        let lists = loader().load(&[http(addr, "/hosts")]).await;

        assert_eq!(lists, []);
    }

    #[tokio::test]
    async fn announced_oversized_list_is_rejected() {
        let addr = http_server(Reply::Announced(10 * 1024 * 1024)).await;

        let lists = loader().load(&[http(addr, "/huge")]).await;

        assert_eq!(lists, []);
    }

    // A server can omit Content-Length (or lie about it): the limit must
    // hold on the bytes actually received.
    #[tokio::test]
    async fn oversized_list_without_length_is_rejected() {
        let addr = http_server(Reply::Unsized("ads.example.com\n".repeat(200))).await;

        let lists = loader().load(&[http(addr, "/huge")]).await;

        assert_eq!(lists, []);
    }

    #[tokio::test]
    async fn list_just_under_the_limit_is_accepted() {
        let body = "ads.example.com\n".repeat(64);
        assert_eq!(body.len(), 1024);
        let addr = http_server(Reply::Unsized(body)).await;

        let lists = loader().load(&[http(addr, "/hosts")]).await;

        assert_eq!(lists.len(), 1);
    }

    #[tokio::test]
    async fn failing_list_does_not_affect_the_others() {
        let good = http_server(Reply::Ok(200, "a.example.com".to_owned())).await;
        let bad = http_server(Reply::Ok(500, String::new())).await;
        let file = list_file("b.example.com");

        let lists = loader()
            .load(&[
                http(good, "/a"),
                http(bad, "/b"),
                ListSource::File(file.path().into()),
            ])
            .await;

        let deny: Vec<_> = lists.iter().map(|list| list.deny.clone()).collect();
        assert_eq!(
            deny,
            [
                vec![Rule::Exact("a.example.com".to_owned())],
                vec![Rule::Exact("b.example.com".to_owned())],
            ]
        );
    }

    #[tokio::test]
    async fn lists_are_downloaded_concurrently() {
        // Two slow lists: sequential loading would take twice the timeout.
        let slow_a = http_server(Reply::Silent).await;
        let slow_b = http_server(Reply::Silent).await;
        let started = std::time::Instant::now();

        loader()
            .load(&[http(slow_a, "/a"), http(slow_b, "/b")])
            .await;

        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
    }
}
