//! Fetching the blocklists named in the configuration.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::{ListConfig, ListSource};
use crate::lists::{BareDomains, ParsedList, parse_list_with};

/// Bounds on list downloads, so no list can stall startup or exhaust memory.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    /// Larger lists are rejected: the biggest public lists are a few dozen MiB.
    pub max_bytes: usize,
    /// Lists loaded at the same time; bounds peak memory to about
    /// `concurrency × max_bytes`.
    pub concurrency: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_bytes: 64 * 1024 * 1024,
            concurrency: 4,
        }
    }
}

/// Redirects followed at most, like browsers' lower bound.
pub const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum FetchError {
    #[error("timed out")]
    Timeout,
    #[error("list larger than {0} bytes")]
    TooLarge(usize),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("{0}")]
    Failed(String),
}

/// Loads blocklists from files and HTTP(S) URLs.
#[derive(Debug, Clone)]
pub struct ListLoader {
    client: reqwest::Client,
    limits: Limits,
}

impl ListLoader {
    /// Fails only if the TLS stack cannot be initialized.
    pub fn new(limits: Limits) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(limits.timeout)
            .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if allows_redirect(attempt.previous(), attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.error("redirect refused: HTTPS downgrade or too many hops")
                }
            }))
            .build()?;
        Ok(Self { client, limits })
    }

    /// Loads and parses every list, at most `limits.concurrency` at a time.
    /// A list that cannot be loaded is logged and skipped: DNS must keep
    /// working without it. Lists keep the order of `sources`.
    pub async fn load(&self, lists: &[ListConfig]) -> Vec<ParsedList> {
        self.load_each(lists)
            .await
            .into_iter()
            .filter_map(|(_, result)| result.ok())
            .collect()
    }

    /// Loads every list like [`ListLoader::load`], and returns each one with
    /// its outcome, in configuration order.
    pub async fn load_each(&self, lists: &[ListConfig]) -> Vec<(ListConfig, ListResult)> {
        let permits = Arc::new(Semaphore::new(self.limits.concurrency.max(1)));
        let mut tasks = JoinSet::new();
        for (index, config) in lists.iter().cloned().enumerate() {
            if config.source.is_insecure() {
                tracing::warn!(list = %config.source, "blocklist fetched over plain HTTP, prefer HTTPS");
            }
            let loader = self.clone();
            let permits = Arc::clone(&permits);
            tasks.spawn(async move {
                // The semaphore is never closed, so acquiring cannot fail.
                let _permit = permits.acquire_owned().await;
                let result = match loader.fetch(&config.source).await {
                    Ok(text) => parse(text, config.bare_domains).await.map(|mut list| {
                        list.origin = config.source.label();
                        list
                    }),
                    Err(error) => Err(error),
                };
                (index, config, result)
            });
        }

        let mut results = Vec::with_capacity(lists.len());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, config, result)) => {
                    match &result {
                        Ok(list) => tracing::info!(
                            list = %config.source,
                            deny = list.deny.len(),
                            allow = list.allow.len(),
                            skipped = list.skipped,
                            "blocklist loaded"
                        ),
                        Err(error) => tracing::warn!(
                            list = %config.source,
                            %error,
                            "cannot load blocklist, skipped"
                        ),
                    }
                    results.push((index, config, result));
                }
                Err(error) => tracing::error!(%error, "blocklist task failed"),
            }
        }
        results.sort_by_key(|(index, ..)| *index);
        results
            .into_iter()
            .map(|(_, config, result)| (config, result))
            .collect()
    }

    /// The text of one list.
    pub async fn fetch(&self, source: &ListSource) -> Result<String, FetchError> {
        match source {
            ListSource::File(path) => self.read_file(path).await,
            ListSource::Http(url) => self.download(url).await,
        }
    }

    async fn read_file(&self, path: &Path) -> Result<String, FetchError> {
        let file = tokio::fs::File::open(path).await.map_err(failed)?;
        let mut bytes = Vec::new();
        // Reading one byte past the limit tells the file is too large without
        // loading all of it. The outcome is the same without `take`, so only
        // memory use (not a test) can tell it apart.
        file.take(self.limit_u64() + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(failed)?;
        self.check_size(bytes.len())?;
        Ok(decode(bytes))
    }

    /// Downloads `url`, refusing bodies over the limit whatever the headers say.
    async fn download(&self, url: &str) -> Result<String, FetchError> {
        let mut response = self.client.get(url).send().await.map_err(from_reqwest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        let announced = response.content_length();
        if announced.is_some_and(|len| len > self.limit_u64()) {
            return Err(FetchError::TooLarge(self.limits.max_bytes));
        }
        // Reserving the announced size avoids doubling the capacity past it.
        let mut bytes = Vec::with_capacity(announced.map_or(0, |len| {
            usize::try_from(len).unwrap_or(self.limits.max_bytes)
        }));
        while let Some(chunk) = response.chunk().await.map_err(from_reqwest)? {
            self.check_size(bytes.len() + chunk.len())?;
            bytes.extend_from_slice(&chunk);
        }
        Ok(decode(bytes))
    }

    fn check_size(&self, len: usize) -> Result<(), FetchError> {
        if len > self.limits.max_bytes {
            Err(FetchError::TooLarge(self.limits.max_bytes))
        } else {
            Ok(())
        }
    }

    fn limit_u64(&self) -> u64 {
        u64::try_from(self.limits.max_bytes).unwrap_or(u64::MAX)
    }
}

/// The outcome of loading one list.
pub type ListResult = Result<ParsedList, FetchError>;

/// The last valid version of each configured list, so that a list failing
/// on refresh keeps blocking with its previous content (ADR 0007).
#[derive(Debug, Clone, Default)]
pub struct ListStore {
    lists: HashMap<ListConfig, Arc<ParsedList>>,
}

impl ListStore {
    /// Records fresh results: a list that loaded replaces its previous
    /// version; a list that failed keeps it, if it had one.
    pub fn update(&mut self, results: Vec<(ListConfig, ListResult)>) {
        for (config, result) in results {
            match result {
                Ok(list) => {
                    self.lists.insert(config, Arc::new(list));
                }
                Err(_) if self.lists.contains_key(&config) => {
                    tracing::warn!(list = %config.source, "keeping the previous version of the blocklist");
                }
                Err(_) => {}
            }
        }
    }

    /// Forgets lists that are no longer configured.
    pub fn retain(&mut self, configured: &[ListConfig]) {
        self.lists.retain(|config, _| configured.contains(config));
    }

    /// Configured lists that have no version yet, in configuration order.
    #[must_use]
    pub fn missing(&self, configured: &[ListConfig]) -> Vec<ListConfig> {
        configured
            .iter()
            .filter(|config| !self.lists.contains_key(config))
            .cloned()
            .collect()
    }

    /// Every stored list, in no particular order.
    pub fn lists(&self) -> impl Iterator<Item = &ParsedList> {
        self.lists.values().map(AsRef::as_ref)
    }

    /// Shared handles to every stored list, to build a policy elsewhere
    /// (on a blocking thread) without copying the rules.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Arc<ParsedList>> {
        self.lists.values().cloned().collect()
    }
}

/// Parses off the async runtime: a list of several MiB takes long enough to
/// delay queries if parsed on a runtime worker during a refresh.
async fn parse(text: String, bare_domains: BareDomains) -> ListResult {
    tokio::task::spawn_blocking(move || parse_list_with(&text, bare_domains))
        .await
        .map_err(|error| FetchError::Failed(format!("parsing task failed: {error}")))
}

/// Whether to follow a redirect to `next` after visiting `previous`:
/// never from HTTPS down to plain HTTP, and at most [`MAX_REDIRECTS`] hops.
#[must_use]
pub fn allows_redirect(previous: &[Url], next: &Url) -> bool {
    let downgrade = next.scheme() == "http" && previous.iter().any(|url| url.scheme() == "https");
    previous.len() < MAX_REDIRECTS && !downgrade
}

/// Lists are meant to be UTF-8; stray bytes become U+FFFD instead of failing
/// the whole list. Valid text is not copied.
fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as map_err(from_reqwest)"
)]
fn from_reqwest(error: reqwest::Error) -> FetchError {
    if error.is_timeout() {
        FetchError::Timeout
    } else {
        // reqwest's message alone hides the cause (DNS, TLS, redirect…).
        let mut message = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        FetchError::Failed(message)
    }
}

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(failed)")]
fn failed(error: std::io::Error) -> FetchError {
    FetchError::Failed(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Barrier;

    use super::*;
    use crate::config::ListConfig;
    use crate::filter::Rule;
    use crate::lists::BareDomains;

    const MAX_BYTES: usize = 1024;

    fn list_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    fn configs(sources: &[ListSource]) -> Vec<ListConfig> {
        sources.iter().cloned().map(ListConfig::from).collect()
    }

    fn loader() -> ListLoader {
        loader_with(4)
    }

    fn loader_with(concurrency: usize) -> ListLoader {
        ListLoader::new(Limits {
            timeout: Duration::from_millis(500),
            max_bytes: MAX_BYTES,
            concurrency,
        })
        .unwrap()
    }

    /// Counts connections being served at the same time.
    #[derive(Default)]
    struct Gauge {
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    /// What the test HTTP server sends back.
    #[derive(Clone)]
    enum Reply {
        /// Status and body, with a correct Content-Length.
        Ok(u16, String),
        /// Body without Content-Length, delimited by closing the connection.
        Unsized(String),
        /// Headers announcing `usize` bytes, then the connection stays open
        /// without a body: only the Content-Length check can end it early.
        Announced(usize),
        /// Never answers.
        Silent,
        /// 302 to the given location.
        Redirect(String),
        /// 302 to the same path, forever, counting requests.
        RedirectLoop(Arc<AtomicUsize>),
        /// Answers once every party has connected: proves concurrency.
        AfterBarrier(Arc<Barrier>, String),
        /// Holds each connection briefly while measuring concurrency.
        Measured(Arc<Gauge>, String),
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
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
                        Reply::Announced(len) => {
                            let headers =
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
                            let _ = stream.write_all(headers.as_bytes()).await;
                            std::future::pending::<()>().await;
                            return;
                        }
                        Reply::Silent => {
                            std::future::pending::<()>().await;
                            return;
                        }
                        Reply::Redirect(location) => format!(
                            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        ),
                        Reply::RedirectLoop(hits) => {
                            hits.fetch_add(1, Ordering::SeqCst);
                            "HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                        }
                        Reply::AfterBarrier(barrier, body) => {
                            barrier.wait().await;
                            ok(&body)
                        }
                        Reply::Measured(gauge, body) => {
                            let active = gauge.active.fetch_add(1, Ordering::SeqCst) + 1;
                            gauge.peak.fetch_max(active, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            gauge.active.fetch_sub(1, Ordering::SeqCst);
                            ok(&body)
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

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn file_list_is_read_and_parsed() {
        let file = list_file("0.0.0.0 ads.example.com\n||tracker.example^\n");

        let lists = loader()
            .load(&configs(&[ListSource::File(file.path().into())]))
            .await;

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
    async fn wildcard_option_reaches_the_parser() {
        let file = list_file("ads.example.com\n0.0.0.0 t.example.net\n");
        let wildcard = ListConfig {
            source: ListSource::File(file.path().into()),
            bare_domains: BareDomains::WithSubdomains,
        };

        let lists = loader().load(&[wildcard]).await;

        assert_eq!(
            lists[0].deny,
            vec![
                Rule::Subtree("ads.example.com".to_owned()),
                Rule::Subtree("t.example.net".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn loaded_list_is_labelled_with_its_source() {
        let file = list_file("ads.example.com");
        let source = ListSource::File(file.path().into());

        let lists = loader().load(&configs(std::slice::from_ref(&source))).await;

        assert_eq!(lists[0].origin, source.label());
    }

    #[tokio::test]
    async fn unreadable_list_is_skipped() {
        let file = list_file("ads.example.com");

        let lists = loader()
            .load(&configs(&[
                ListSource::File("/nonexistent/list.txt".into()),
                ListSource::File(file.path().into()),
            ]))
            .await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn oversized_file_list_is_rejected() {
        let file = list_file(&"a".repeat(MAX_BYTES + 1));

        let error = loader()
            .fetch(&ListSource::File(file.path().into()))
            .await
            .unwrap_err();

        assert_eq!(error, FetchError::TooLarge(MAX_BYTES));
    }

    #[tokio::test]
    async fn http_list_is_downloaded_and_parsed() {
        let addr = http_server(Reply::Ok(200, "0.0.0.0 ads.example.com\n".to_owned())).await;

        let lists = loader().load(&configs(&[http(addr, "/hosts")])).await;

        assert_eq!(lists.len(), 1);
        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn error_status_is_reported() {
        let addr = http_server(Reply::Ok(404, "ads.example.com".to_owned())).await;

        let error = loader().fetch(&http(addr, "/missing")).await.unwrap_err();

        assert_eq!(error, FetchError::Status(404));
    }

    // Paused clock: tokio jumps straight to the timeout once only the silent
    // server is left, so the test neither waits nor depends on CI speed.
    #[tokio::test(start_paused = true)]
    async fn silent_server_times_out() {
        let addr = http_server(Reply::Silent).await;

        let error = loader().fetch(&http(addr, "/slow")).await.unwrap_err();

        assert_eq!(error, FetchError::Timeout);
    }

    #[tokio::test]
    async fn unreachable_server_is_a_failure() {
        // Bind then drop: nothing listens on this port any more.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();

        let error = loader().fetch(&http(addr, "/hosts")).await.unwrap_err();

        assert!(matches!(error, FetchError::Failed(_)), "{error:?}");
    }

    // The server never sends the body: without the Content-Length check,
    // the download would end in a timeout instead.
    #[tokio::test]
    async fn announced_oversized_list_is_rejected_from_its_headers() {
        let addr = http_server(Reply::Announced(MAX_BYTES + 1)).await;

        let error = loader().fetch(&http(addr, "/huge")).await.unwrap_err();

        assert_eq!(error, FetchError::TooLarge(MAX_BYTES));
    }

    // A server can omit Content-Length (or lie about it): the limit must
    // hold on the bytes actually received.
    #[tokio::test]
    async fn unannounced_list_one_byte_over_the_limit_is_rejected() {
        let addr = http_server(Reply::Unsized("a".repeat(MAX_BYTES + 1))).await;

        let error = loader().fetch(&http(addr, "/huge")).await.unwrap_err();

        assert_eq!(error, FetchError::TooLarge(MAX_BYTES));
    }

    #[tokio::test]
    async fn list_exactly_at_the_limit_is_accepted() {
        let addr = http_server(Reply::Unsized("a".repeat(MAX_BYTES))).await;

        let text = loader().fetch(&http(addr, "/hosts")).await.unwrap();

        assert_eq!(text.len(), MAX_BYTES);
    }

    #[tokio::test]
    async fn invalid_utf8_is_replaced_not_fatal() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"ads.example.com\n\xFF\n").unwrap();

        let lists = loader()
            .load(&configs(&[ListSource::File(file.path().into())]))
            .await;

        assert_eq!(
            lists[0].deny,
            vec![Rule::Exact("ads.example.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn redirect_is_followed() {
        let target = http_server(Reply::Ok(200, "ads.example.com".to_owned())).await;
        let origin = http_server(Reply::Redirect(format!("http://{target}/hosts"))).await;

        let text = loader().fetch(&http(origin, "/old")).await.unwrap();

        assert_eq!(text, "ads.example.com");
    }

    // Proves the policy is wired into the client: reqwest's default would
    // follow 10 redirects (11 requests) and fail with another message.
    #[tokio::test]
    async fn redirect_loop_is_cut_by_our_policy() {
        let hits = Arc::new(AtomicUsize::new(0));
        let addr = http_server(Reply::RedirectLoop(Arc::clone(&hits))).await;

        let error = loader().fetch(&http(addr, "/loop")).await.unwrap_err();

        assert!(
            matches!(&error, FetchError::Failed(message) if message.contains("redirect refused")),
            "{error:?}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), MAX_REDIRECTS);
    }

    #[test]
    fn redirect_policy_refuses_https_to_http_downgrade() {
        let previous = [url("https://lists.example/hosts")];

        assert!(!allows_redirect(
            &previous,
            &url("http://mirror.example/hosts")
        ));
        assert!(allows_redirect(
            &previous,
            &url("https://mirror.example/hosts")
        ));
    }

    #[test]
    fn redirect_policy_refuses_downgrade_anywhere_in_the_chain() {
        let previous = [url("https://a.example/"), url("https://b.example/")];

        assert!(!allows_redirect(&previous, &url("http://c.example/")));
    }

    #[test]
    fn redirect_policy_allows_plain_http_chains() {
        assert!(allows_redirect(
            &[url("http://a.example/")],
            &url("http://b.example/")
        ));
    }

    #[test]
    fn redirect_policy_limits_the_number_of_hops() {
        let previous: Vec<Url> = (0..MAX_REDIRECTS)
            .map(|i| url(&format!("https://hop{i}.example/")))
            .collect();

        assert!(allows_redirect(
            &previous[..MAX_REDIRECTS - 1],
            &url("https://next.example/")
        ));
        assert!(!allows_redirect(&previous, &url("https://next.example/")));
    }

    #[tokio::test]
    async fn failing_list_does_not_affect_the_others() {
        let good = http_server(Reply::Ok(200, "a.example.com".to_owned())).await;
        let bad = http_server(Reply::Ok(500, String::new())).await;
        let file = list_file("b.example.com");

        let lists = loader()
            .load(&configs(&[
                http(good, "/a"),
                http(bad, "/b"),
                ListSource::File(file.path().into()),
            ]))
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

    // Both downloads must be in flight together for the server to answer;
    // sequential loading would time out on the first one.
    #[tokio::test]
    async fn lists_are_downloaded_concurrently() {
        let barrier = Arc::new(Barrier::new(2));
        let a = http_server(Reply::AfterBarrier(
            Arc::clone(&barrier),
            "a.example.com".to_owned(),
        ))
        .await;
        let b = http_server(Reply::AfterBarrier(barrier, "b.example.com".to_owned())).await;

        let lists = loader()
            .load(&configs(&[http(a, "/a"), http(b, "/b")]))
            .await;

        assert_eq!(lists.len(), 2);
    }

    // A semaphore without permits would block forever.
    #[tokio::test]
    async fn zero_concurrency_still_loads_lists() {
        let file = list_file("ads.example.com");

        let lists = tokio::time::timeout(
            Duration::from_secs(5),
            loader_with(0).load(&configs(&[ListSource::File(file.path().into())])),
        )
        .await
        .expect("load must not deadlock");

        assert_eq!(lists.len(), 1);
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let gauge = Arc::new(Gauge::default());
        let addr = http_server(Reply::Measured(
            Arc::clone(&gauge),
            "a.example.com".to_owned(),
        ))
        .await;
        let sources: Vec<_> = (0..6).map(|i| http(addr, &format!("/{i}"))).collect();

        let lists = loader_with(2).load(&configs(&sources)).await;

        assert_eq!(lists.len(), 6);
        assert!(
            gauge.peak.load(Ordering::SeqCst) <= 2,
            "peak {}",
            gauge.peak.load(Ordering::SeqCst)
        );
    }

    mod store {
        use super::*;

        fn config(name: &str) -> ListConfig {
            ListSource::File(format!("/lists/{name}.txt").into()).into()
        }

        fn list(domain: &str) -> ParsedList {
            ParsedList {
                deny: vec![Rule::Exact(domain.to_owned())],
                ..ParsedList::default()
            }
        }

        fn denied(store: &ListStore) -> Vec<Rule> {
            let mut rules: Vec<Rule> = store.lists().flat_map(|l| l.deny.clone()).collect();
            rules.sort_by_key(|rule| format!("{rule:?}"));
            rules
        }

        #[test]
        fn loaded_list_is_stored() {
            let mut store = ListStore::default();

            store.update(vec![(config("a"), Ok(list("a.example.com")))]);

            assert_eq!(denied(&store), [Rule::Exact("a.example.com".to_owned())]);
        }

        #[test]
        fn failed_refresh_keeps_the_previous_version() {
            let mut store = ListStore::default();
            store.update(vec![(config("a"), Ok(list("a.example.com")))]);

            store.update(vec![(config("a"), Err(FetchError::Timeout))]);

            assert_eq!(denied(&store), [Rule::Exact("a.example.com".to_owned())]);
        }

        #[test]
        fn failed_list_without_previous_version_is_absent() {
            let mut store = ListStore::default();

            store.update(vec![(config("a"), Err(FetchError::Status(404)))]);

            assert_eq!(denied(&store), []);
        }

        #[test]
        fn successful_refresh_replaces_the_previous_version() {
            let mut store = ListStore::default();
            store.update(vec![(config("a"), Ok(list("old.example.com")))]);

            store.update(vec![(config("a"), Ok(list("new.example.com")))]);

            assert_eq!(denied(&store), [Rule::Exact("new.example.com".to_owned())]);
        }

        #[test]
        fn lists_no_longer_configured_are_forgotten() {
            let mut store = ListStore::default();
            store.update(vec![
                (config("a"), Ok(list("a.example.com"))),
                (config("b"), Ok(list("b.example.com"))),
            ]);

            store.retain(&[config("b")]);

            assert_eq!(denied(&store), [Rule::Exact("b.example.com".to_owned())]);
        }

        // The same URL with another wildcard setting is another list.
        #[test]
        fn list_identity_includes_its_wildcard_setting() {
            let mut store = ListStore::default();
            let exact = config("a");
            let wildcard = ListConfig {
                bare_domains: BareDomains::WithSubdomains,
                ..exact.clone()
            };
            store.update(vec![(exact, Ok(list("a.example.com")))]);

            assert_eq!(store.missing(std::slice::from_ref(&wildcard)), [wildcard]);
        }

        #[test]
        fn missing_lists_keep_configuration_order() {
            let mut store = ListStore::default();
            store.update(vec![(config("b"), Ok(list("b.example.com")))]);

            let missing = store.missing(&[config("c"), config("b"), config("a")]);

            assert_eq!(missing, [config("c"), config("a")]);
        }
    }

    #[tokio::test]
    async fn load_each_reports_every_list_with_its_outcome() {
        let file = list_file("ads.example.com");
        let lists = configs(&[
            ListSource::File(file.path().into()),
            ListSource::File("/nonexistent/list.txt".into()),
        ]);

        let results = loader().load_each(&lists).await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, lists[0]);
        assert_eq!(
            results[0].1.as_ref().unwrap().deny,
            [Rule::Exact("ads.example.com".to_owned())]
        );
        assert_eq!(results[1].0, lists[1]);
        assert!(
            matches!(results[1].1, Err(FetchError::Failed(_))),
            "{:?}",
            results[1].1
        );
    }
}
