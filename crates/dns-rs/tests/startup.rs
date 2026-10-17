//! The real binary, while its blocklists load: Kubernetes probes must see a
//! live process (liveness 200) that is not ready yet (readiness 503), or a
//! liveness probe would kill pods whose lists are slow to download.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Kills the binary even when an assertion fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Status code of `GET path`, or None if nothing answers.
fn http_status(port: u16, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}

/// Polls until `check` holds, for at most `limit`.
fn eventually(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn probes_answer_while_blocklists_load() {
    // A list server that holds the request until the test lets it answer.
    let list_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let list_port = list_server.local_addr().unwrap().port();
    let (release, released) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (mut stream, _) = list_server.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let _ = released.recv();
        let body = "ads.example.com\n";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("dns-rs.toml");
    std::fs::write(
        &config,
        format!("[blocking]\nlists = ['http://127.0.0.1:{list_port}/list']\n"),
    )
    .unwrap();
    let http_port = free_port();
    let _dns_rs = Running(
        Command::new(env!("CARGO_BIN_EXE_dns-rs"))
            .env("DNS_RS_CONFIG", &config)
            .env("DNS_RS_LISTEN", format!("127.0.0.1:{}", free_port()))
            .env("DNS_RS_HTTP_LISTEN", format!("127.0.0.1:{http_port}"))
            .env("RUST_LOG", "error")
            .spawn()
            .unwrap(),
    );

    // While the list is held: alive, not ready.
    let alive = eventually(Duration::from_secs(10), || {
        http_status(http_port, "/healthz") == Some(200)
    });
    let ready_while_loading = http_status(http_port, "/readyz");
    release.send(()).unwrap();
    let ready_after = eventually(Duration::from_secs(10), || {
        http_status(http_port, "/readyz") == Some(200)
    });

    assert!(alive, "liveness never answered while the list was loading");
    assert_eq!(ready_while_loading, Some(503));
    assert!(ready_after, "never became ready once the list was served");
}
