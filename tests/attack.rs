//! Attack the decoy the way public exploits do, and check it logged it.
//!
//! Starts the release binary on loopback, once per persona, sends logins, known
//! exploit requests, Modbus reads/writes and junk, then asserts on the log.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

// Each persona test uses its own port block so tests can run in parallel.

struct Decoy {
    child: Child,
    log_path: PathBuf,
}

impl Drop for Decoy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bin() -> PathBuf {
    // target/release/fridgep0t next to the test binary's target dir.
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    if p.ends_with("deps") {
        p.pop();
    }
    p.push("fridgep0t");
    p
}

fn start(persona: &str, http_port: u16, extra: &[(&str, &str)]) -> Decoy {
    start_with(persona, http_port, extra, std::process::Stdio::null())
}

fn start_with(persona: &str, http_port: u16, extra: &[(&str, &str)], stdout: std::process::Stdio) -> Decoy {
    let dir = std::env::temp_dir().join(format!("fridgep0t-{persona}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // One log per decoy: several tests run the same persona in parallel.
    let log_path = dir.join(format!("{persona}-{http_port}.jsonl"));
    let _ = std::fs::remove_file(&log_path);
    let mut cmd = Command::new(bin());
    cmd.env("PERSONA", persona)
        .env("BIND", "127.0.0.1")
        .env("HTTP_PORT", http_port.to_string())
        .env("LOG_PATH", &log_path)
        .env("DEVICE_TZ", "Europe/Rome")
        .stdout(stdout);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn decoy");
    wait_port(("127.0.0.1", http_port));
    Decoy { child, log_path }
}

fn wait_port(addr: impl ToSocketAddrs + Clone) {
    for _ in 0..100 {
        if TcpStream::connect(addr.clone()).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("decoy did not open its port");
}

fn events(path: &PathBuf) -> Vec<Value> {
    std::thread::sleep(Duration::from_millis(300));
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

type Reply = (u16, Vec<(String, String)>, String);

/// Minimal HTTP/1.1 request over a fresh connection; returns (status, headers, body).
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> Reply {
    request(port, method, path, body, "").0
}

/// Like http(), but with an Authorization header.
fn http_auth(port: u16, method: &str, path: &str, auth: &str) -> Reply {
    request(port, method, path, None, &format!("Authorization: {auth}\r\n")).0
}

/// Send one request with `Connection: close`; returns the reply and the stream,
/// positioned right after the body, so a caller can check the server closed.
fn request(port: u16, method: &str, path: &str, body: Option<&str>, extra: &str) -> (Reply, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    // Read headers first, then exactly Content-Length body bytes, so a
    // keep-alive response does not block until timeout.
    let mut raw = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        match stream.read(&mut tmp) {
            Ok(0) => break raw.len().saturating_sub(4),
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(_) => break raw.len().saturating_sub(4),
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let content_len: usize = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body_bytes = raw.get(header_end + 4..).unwrap_or(&[]).to_vec();
    while body_bytes.len() < content_len {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body_bytes.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let status: u16 = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    (
        (status, headers, String::from_utf8_lossy(&body_bytes).into_owned()),
        stream,
    )
}

/// Send raw request bytes with `Connection: close` already in them; return the raw reply.
fn raw_http(port: u16, request: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request).unwrap();
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    all
}

/// Base64-encode "user:pass" for an HTTP Basic header value.
fn basic(user: &str, pass: &str) -> String {
    const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{pass}");
    let bytes = raw.as_bytes();
    let mut out = String::from("Basic ");
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        out.push(TBL[(b[0] >> 2) as usize] as char);
        out.push(TBL[(((b[0] & 0x3) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TBL[(((b[1] & 0xf) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[(b[2] & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn modbus(stream: &mut TcpStream, tid: u16, pdu: &[u8], unit: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&tid.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    frame.push(unit);
    frame.extend_from_slice(pdu);
    stream.write_all(&frame).unwrap();
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).unwrap();
    let length = u16::from_be_bytes([header[4], header[5]]);
    let mut reply = vec![0u8; (length - 1) as usize];
    stream.read_exact(&mut reply).unwrap();
    reply
}

#[test]
fn danfoss_persona() {
    const HP: u16 = 18080;
    const MP: u16 = 15020;
    let decoy = start("danfoss", HP, &[("MODBUS_PORT", MP.to_string().as_str())]);
    wait_port(("127.0.0.1", MP));

    // Login page present and nginx-flavoured.
    let (status, headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(page.contains("System Manager 800A"), "login page title missing");
    assert!(page.contains("<title>Danfoss StoreView</title>"));
    let server = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("server"));
    assert_eq!(server.map(|(_, v)| v.as_str()), Some("nginx"));
    assert!(headers.iter().any(|(k, _)| k == "ETag"));
    // Header order: Server, Date, Content-Type, Content-Length, Last-Modified...
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        &names[..5],
        &[
            "Server",
            "Date",
            "Content-Type",
            "Content-Length",
            "Last-Modified"
        ]
    );

    // `Connection: close` is honoured on the keep-alive page: nginx echoes it and closes.
    {
        let (reply, mut s) = request(HP, "GET", "/", None, "");
        assert_eq!(reply.0, 200);
        assert!(
            reply.1.iter().any(|(k, v)| k == "Connection" && v == "close"),
            "server should echo close"
        );
        let mut buf = [0u8; 16];
        assert_eq!(
            s.read(&mut buf).ok(),
            Some(0),
            "server should close after a Connection: close request"
        );
    }

    // Pipelined requests on the keep-alive page are both answered.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        let text = String::from_utf8_lossy(&all);
        assert_eq!(
            text.matches("HTTP/1.1 200 OK").count(),
            2,
            "both pipelined requests should be answered"
        );
    }

    // An oversized body is refused and the connection closed, so its tail can
    // never be parsed as a second request.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let tail = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut raw = format!(
            "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            9000 + tail.len()
        )
        .into_bytes();
        raw.extend_from_slice(&vec![b'x'; 9000]);
        raw.extend_from_slice(tail);
        let _ = s.write_all(&raw); // the server may already have closed on us
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        let text = String::from_utf8_lossy(&all);
        assert!(
            text.starts_with("HTTP/1.1 413 "),
            "oversized request gets a 413: {text:?}"
        );
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            1,
            "and its tail is never answered"
        );
    }

    // A body cut short by EOF is never dispatched: the defrost on node 7 must not land.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let cmd = r#"<cmd action="start_defrost" node="7" user="Supervisor" password="12345"/>"#;
        let raw = format!("POST /html/xml.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{cmd}");
        let _ = s.write_all(raw.as_bytes());
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        assert!(
            all.is_empty(),
            "no response to a truncated request, got {} bytes",
            all.len()
        );
    }

    // A repeated Connection header cannot hide `close`.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n")
            .unwrap();
        let mut all = Vec::new();
        let closed = s.read_to_end(&mut all).is_ok();
        assert!(
            closed,
            "server should close after `Connection: close` + `Connection: keep-alive`"
        );
        assert_eq!(
            String::from_utf8_lossy(&all).matches("HTTP/1.1 200 OK").count(),
            1
        );
    }

    // A malformed Content-Length is refused, not read as zero.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = s.write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        let text = String::from_utf8_lossy(&all);
        assert!(
            text.starts_with("HTTP/1.1 400 "),
            "malformed Content-Length gets a 400: {text:?}"
        );
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            1,
            "and what follows it is never answered"
        );
    }

    // The same login arrives in three TCP segments with pauses: still one request.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = r#"<cmd action="getauth" user="Supervisor" password="12345"/>"#;
        let head = format!(
            "POST /html/xml.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let whole = format!("{head}{body}");
        let (a, rest) = whole.split_at(10);
        let (b, c) = rest.split_at(head.len() + 5 - 10);
        for part in [a, b, c] {
            s.write_all(part.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        assert!(
            String::from_utf8_lossy(&all).contains("session_token"),
            "segmented login should be served"
        );
    }

    // A malformed request is refused the way nginx refuses it: a 400 page (413
    // for an oversized body), never the silence that would mark a decoy, and
    // never the page it asked for.
    {
        let big = format!(
            "POST /html/xml.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 9000\r\n\r\n{}",
            "a".repeat(9000)
        );
        let cases: [(&[u8], &str); 4] = [
            (b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", "400 Bad Request"),
            (
                b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length : 0\r\nConnection: close\r\n\r\n",
                "400 Bad Request",
            ),
            (b"get / HTTP/1.1\r\nHost: x\r\n\r\n", "400 Bad Request"),
            (big.as_bytes(), "413 Request Entity Too Large"),
        ];
        for (raw, status) in cases {
            let got = String::from_utf8_lossy(&raw_http(HP, raw)).into_owned();
            assert!(
                got.starts_with(&format!("HTTP/1.1 {status}\r\nServer: nginx\r\n")),
                "{got:?}"
            );
            assert!(
                got.contains(&format!("<center><h1>{status}</h1></center>")),
                "{got:?}"
            );
            assert!(!got.contains("StoreView"), "a refused request must not be served");
        }
    }

    // Unknown paths 404; xml.cgi rejects GET; the login page is a static file,
    // so anything but GET/HEAD on it is 405. nginx error pages carry no charset.
    for (method, path, status) in [
        ("GET", "/wp-login.php", 404),
        ("GET", "/html/xml.cgi", 405),
        ("DELETE", "/", 405),
        ("POST", "/", 405),
    ] {
        let (got, headers, _) = http(HP, method, path, None);
        assert_eq!(got, status, "{method} {path}");
        let ctype = headers.iter().find(|(k, _)| k == "Content-Type");
        assert_eq!(
            ctype.map(|(_, v)| v.as_str()),
            Some("text/html"),
            "{method} {path}"
        );
    }

    // Weak login succeeds via the XML API.
    let (_, _, resp) = http(
        HP,
        "POST",
        "/html/xml.cgi",
        Some(r#"<cmd action="getauth" user="Supervisor" password="12345" lang="English"/>"#),
    );
    assert!(resp.contains("session_token"), "weak login should be granted");

    // Code-of-the-day bypass is tagged.
    let (_, _, _) = http(
        HP,
        "POST",
        "/html/xml.cgi",
        Some(r#"<cmd action="getauth" user="x" password="00000" eds_only="1"/>"#),
    );
    // Path traversal is tagged.
    let (_, _, _) = http(
        HP,
        "POST",
        "/html/xml.cgi",
        Some(r#"<cmd action="get_file" filename="../../etc/passwd"/>"#),
    );

    // Start a defrost from a (pre-4.0 style) authenticated command.
    let (_, _, _) = http(
        HP,
        "POST",
        "/html/xml.cgi",
        Some(r#"<cmd action="start_defrost" node="1" user="Supervisor" password="12345"/>"#),
    );

    // Malformed request line must not leak a stock error page.
    {
        let mut s = TcpStream::connect(("127.0.0.1", HP)).unwrap();
        s.write_all(b"\x16\x03\x01garbage\r\n\r\n").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
        let text = String::from_utf8_lossy(&buf);
        assert!(!text.contains("Traceback"));
    }

    // Modbus: read case temps, then force a defrost write.
    {
        let mut s = TcpStream::connect(("127.0.0.1", MP)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let read = modbus(&mut s, 1, &[0x03, 0, 0, 0, 8], 1);
        assert_eq!(read[0], 0x03, "read holding registers reply");
        let write = modbus(&mut s, 2, &[0x06, 0, 200, 0, 1], 1);
        assert_eq!(write[0], 0x06, "write single register echo");
        // Device identification.
        let id = modbus(&mut s, 3, &[0x2B, 0x0E, 0x01, 0x00], 1);
        assert_eq!(id[0], 0x2B);
        // The last address is unmapped: exception 2, not a 2-byte reply with no data.
        let exc = modbus(&mut s, 4, &[0x03, 0xFF, 0xFF, 0, 1], 1);
        assert_eq!(
            exc,
            vec![0x83, 0x02],
            "read at 0xFFFF must be an illegal-address exception"
        );
    }

    let ev = events(&decoy.log_path);
    assert!(exploit_seen(&ev, "CVE-2025-41450"), "code-of-the-day not tagged");
    assert!(exploit_seen(&ev, "CVE-2023-25914"), "path traversal not tagged");
    assert!(login_granted(&ev), "a login should have been granted");
    assert!(event_seen(&ev, "control"), "defrost control not logged");
    assert!(defrost_seen(&ev), "a defrost should be flagged");
    assert!(
        !ev.iter().any(|e| e["event"] == "control" && e["node"] == "7"),
        "a truncated defrost command must not be dispatched"
    );
    assert!(
        ev.iter().filter(|e| e["event"] == "bad_request").count() >= 6,
        "garbage, oversized, truncated, bad-length, host-less and malformed-header requests each log bad_request"
    );

    // read_units must report a generated, non-constant store name.
    let (_, _, units) = http(
        HP,
        "POST",
        "/html/xml.cgi",
        Some(r#"<cmd action="read_units" user="Supervisor" password="12345"/>"#),
    );
    assert!(
        units.contains("<store_name>"),
        "read_units should carry a store name"
    );
    assert!(
        !units.contains("Fresh Market 0412"),
        "store name should not be the old constant"
    );
}

#[test]
fn dixell_persona() {
    const HP: u16 = 18081;
    let decoy = start("dixell", HP, &[]);

    // No Server header on the login page.
    let (status, headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(page.contains("XWEB EVO"));
    assert!(
        !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("server")),
        "XWEB EVO sends no Server header"
    );
    // Header names, order and Content-Type as captured from a real unit's
    // banner (see FINGERPRINTS.md).
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "Content-Type",
            "Cache-Control",
            "X-Content-Type-Options",
            "X-Robots-Tag",
            "X-Permitted-Cross-Domain-Policies",
            "Content-Security-Policy",
            "Feature-Policy",
            "Permissions-Policy",
            "Referrer-Policy",
            "Vary",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-UA-Compatible",
            "Content-Length",
            "Date"
        ]
    );
    assert_eq!(headers[0].1, "text/html");
    assert!(
        page.contains("XWEB 500 EVO"),
        "product name as the real login page shows it"
    );

    // Factory login works; bad logins eventually lock out.
    let ok = http(
        HP,
        "POST",
        "/cgi-bin/login.lua",
        Some("action=login&username=Admin&password=Admin"),
    );
    assert!(ok.2.contains("\"result\":\"ok\""), "factory login should succeed");

    // auth_mode bypass is tagged.
    let _ = http(
        HP,
        "POST",
        "/cgi-bin/login.lua",
        Some("action=login&auth_mode=none&username=x&password=y"),
    );

    // CVE-2021-45420: write a file, then read it back — the real exploit check.
    let marker = "dixell-xweb500-filewrite";
    let upload_body = format!("probe.txt\n{marker}");
    let up = http(HP, "POST", "/cgi-bin/logo_extra_upload.cgi", Some(&upload_body));
    assert_eq!(up.0, 200, "upload CGI should answer 200");
    let fetched = http(HP, "GET", "/logo/probe.txt", None);
    assert_eq!(fetched.0, 200, "uploaded file should be retrievable");
    assert!(
        fetched.2.contains(marker),
        "retrieved file should echo the written content"
    );

    // A binary upload round-trips byte for byte: bodies are kept as raw bytes.
    {
        let payload: Vec<u8> = (0..=255u8).collect();
        let mut body = b"blob.bin\n".to_vec();
        body.extend_from_slice(&payload);
        let mut req = format!(
            "POST /cgi-bin/cal_save.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(&body);
        assert!(String::from_utf8_lossy(&raw_http(HP, &req)).starts_with("HTTP/1.1 200"));
        let resp = raw_http(
            HP,
            b"GET /logo/blob.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let split = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response headers")
            + 4;
        assert_eq!(
            &resp[split..],
            &payload[..],
            "binary upload should round-trip byte for byte"
        );
    }

    // An upload that is only a name line stores an empty file, not the name line.
    {
        let req = b"POST /cgi-bin/cal_save.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\nempty.bin\n";
        assert!(String::from_utf8_lossy(&raw_http(HP, req)).starts_with("HTTP/1.1 200"));
        let resp = raw_http(
            HP,
            b"GET /logo/empty.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "empty upload should exist: {:?}",
            text.lines().next()
        );
        assert!(text.contains("Content-Length: 0\r\n"), "and be empty");
    }

    // Directory listing exposes the upload.
    let dir = http(HP, "GET", "/cgi-bin/cal_dir.cgi", None);
    assert!(
        dir.2.contains("probe.txt"),
        "directory listing should show the upload"
    );

    // An upload over the body cap is refused (413), but still tagged in the log.
    {
        let req = format!(
            "POST /cgi-bin/lo_utils.cgi?x=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 9000\r\n\r\n{}",
            "a".repeat(9000)
        );
        let got = raw_http(HP, req.as_bytes());
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 413 "));
        let ev = events(&decoy.log_path);
        assert!(
            ev.iter().any(|e| e["event"] == "bad_request"
                && e["exploit"]
                    .as_str()
                    .is_some_and(|x| x.contains("command execution"))),
            "refused upload should keep its exploit tag"
        );
    }

    let ev = events(&decoy.log_path);
    assert!(exploit_seen(&ev, "CVE-2026-25085"), "auth_mode bypass not tagged");
    assert!(exploit_seen(&ev, "CVE-2021-45420"), "file upload path not tagged");
    assert!(event_seen(&ev, "control"), "file_write not logged as control");
}

#[test]
fn aksc355_persona() {
    const HP: u16 = 18082;
    let decoy = start("aksc355", HP, &[]);

    // Login page present, titled as the AK-SC 355.
    let (status, _headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(page.contains("AK-SC 355"), "login page should name the model");
    assert!(
        page.contains("Forgot Credentials"),
        "reset flow should be present"
    );

    // Documented default login succeeds.
    let ok = http(
        HP,
        "POST",
        "/cgi-bin/login.cgi",
        Some("action=login&user=admin&password=danfoss"),
    );
    assert!(
        ok.2.contains("\"status\":\"ok\""),
        "documented default login should succeed"
    );

    // The Forgot-Credentials flow discloses the MAC, as documented.
    let reset = http(HP, "POST", "/cgi-bin/reset.cgi", Some("action=reset"));
    assert!(reset.2.contains("\"mac\""), "reset should disclose a MAC");
    assert!(reset.2.contains("\"code\""), "reset should return a code");

    let ev = events(&decoy.log_path);
    assert!(login_granted(&ev), "a login should have been granted");
    assert!(
        ev.iter().any(|e| e["event"] == "control"
            && e.get("action") == Some(&Value::String("forgot_credentials".into()))),
        "reset probe should be logged as control"
    );
    // Confirm the firmware the start event reports is in the documented band.
    let start = ev.iter().find(|e| e["event"] == "start").expect("start event");
    let fw = start["firmware"].as_str().unwrap_or("");
    assert!(
        fw.starts_with("3.0") || fw.starts_with("3.1"),
        "firmware {fw} not in 3.09x+ band"
    );
}

#[test]
fn carel_persona() {
    const HP: u16 = 18083;
    let decoy = start("carel", HP, &[]);

    // Demo page present; thttpd Server header; thttpd-style 404.
    let (status, headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(page.contains("pCOWeb"), "demo page should name pCOWeb");
    let server = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("server"));
    assert!(
        server.map(|(_, v)| v.contains("thttpd")).unwrap_or(false),
        "Carel should advertise thttpd"
    );
    // Header set and order of thttpd 2.25b's send_mime(), charset included.
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "Server",
            "Content-Type",
            "Date",
            "Last-Modified",
            "Accept-Ranges",
            "Connection",
            "Content-Length"
        ]
    );
    assert_eq!(headers[1].1, "text/html; charset=iso-8859-1");

    // thttpd's own error pages. They carry no Content-Length, so read to EOF.
    let raw = |req: &[u8]| String::from_utf8_lossy(&raw_http(HP, req)).into_owned();
    let bad = raw(b"GET / HTTP/1.1\r\n\r\n");
    assert!(
        bad.starts_with("HTTP/1.1 400 Bad Request\r\nServer: thttpd/"),
        "{bad:?}"
    );
    assert!(
        bad.contains("\r\nCache-Control: no-cache,no-store\r\n"),
        "{bad:?}"
    );
    assert!(!bad.contains("Content-Length"), "{bad:?}");
    assert!(
        bad.contains("<H2>400 Bad Request</H2>\nYour request has bad syntax"),
        "{bad:?}"
    );
    assert!(bad.ends_with("</ADDRESS>\n</BODY>\n</HTML>\n"), "{bad:?}");
    let refused = raw(b"DELETE / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        refused.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{refused:?}"
    );
    assert!(
        refused.contains("The requested method 'DELETE' is not implemented"),
        "{refused:?}"
    );
    let missing = raw(b"GET /nope?<x> HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(missing.starts_with("HTTP/1.1 404 Not Found\r\n"), "{missing:?}");
    assert!(
        missing.contains("The requested URL '/nope?&lt;x&gt;' was not found on this server."),
        "{missing:?}"
    );
    // thttpd matches method names case-blind and answers in the request's
    // protocol version: `get / HTTP/1.0` is served, as HTTP/1.0.
    assert!(raw(b"get / HTTP/1.0\r\n\r\n").starts_with("HTTP/1.0 200 OK\r\n"));

    // /config/ without auth -> 401 challenge with Basic realm, as the last header.
    let noauth = raw(b"GET /config/pw_changeusers.html HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(noauth.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{noauth:?}");
    assert!(
        noauth.contains("\r\nWWW-Authenticate: Basic realm=\"pCOWeb\"\r\n\r\n<HTML>"),
        "{noauth:?}"
    );
    assert!(
        noauth.contains("Authorization required for the URL '/config/pw_changeusers.html'."),
        "{noauth:?}"
    );

    // With the documented factory credentials, the cleartext disclosure page.
    let auth = basic("httpadmin", "fhttpadmin");
    let got = http_auth(HP, "GET", "/config/pw_changeusers.html", &auth);
    assert_eq!(got.0, 200, "factory creds should pass Basic auth");
    assert!(
        got.2.contains("fhttpadmin"),
        "disclosure page should list cleartext passwords"
    );

    let ev = events(&decoy.log_path);
    assert!(login_granted(&ev), "factory Basic login should be granted");
    assert!(
        exploit_seen(&ev, "CVE-2019-13553"),
        "credential disclosure should be tagged"
    );
}

#[test]
fn eliwell_persona() {
    const HP: u16 = 18084;
    let decoy = start("eliwell", HP, &[]);

    let (status, _headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(page.contains("TelevisGo"), "login page should name TelevisGo");
    assert!(
        page.contains("Save this information"),
        "documented checkbox should be present"
    );

    // Documented default login Administrator / 0.
    let ok = http(HP, "POST", "/login", Some("user=Administrator&password=0"));
    assert!(ok.2.contains("\"result\":\"ok\""), "default login should succeed");

    let ev = events(&decoy.log_path);
    assert!(login_granted(&ev), "a login should have been granted");
}

#[test]
fn rdm_persona() {
    const HP: u16 = 18085;
    let decoy = start("rdm", HP, &[]);

    let (status, _headers, page) = http(HP, "GET", "/", None);
    assert_eq!(status, 200);
    assert!(
        page.contains("Data Manager"),
        "login page should name Data Manager"
    );

    // Documented default password 1234.
    let ok = http(HP, "POST", "/cgi-bin/login.cgi", Some("user=admin&password=1234"));
    assert!(ok.2.contains("\"ok\":true"), "default 1234 login should succeed");

    let ev = events(&decoy.log_path);
    assert!(login_granted(&ev), "a login should have been granted");
}

#[test]
fn https_persona() {
    const HP: u16 = 18087;
    const SP: u16 = 18447;
    let _decoy = start("danfoss", HP, &[("HTTPS_PORT", SP.to_string().as_str())]);
    wait_port(("127.0.0.1", SP));
    let name = rustls::pki_types::ServerName::try_from(String::from("danfoss.test")).unwrap();
    let is_timeout = |r: &std::io::Result<usize>| matches!(r, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));

    // TLS 1.2 handshake, leaf + CA chain, login page served over it.
    {
        let cfg = tls_client::config(&[&rustls::version::TLS12]);
        let mut conn = rustls::ClientConnection::new(cfg, name.clone()).unwrap();
        let mut tcp = TcpStream::connect(("127.0.0.1", SP)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut all = Vec::new();
        let _ = tls.read_to_end(&mut all);
        let text = String::from_utf8_lossy(&all);
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "https login page: {:?}",
            text.lines().next()
        );
        assert!(text.contains("Danfoss StoreView"));
        assert_eq!(conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
        assert_eq!(conn.peer_certificates().map(|c| c.len()), Some(2), "leaf + CA");
    }

    // The TLS 1.2 pin is real: a 1.3-only client never completes a handshake.
    {
        let cfg = tls_client::config(&[&rustls::version::TLS13]);
        let mut conn = rustls::ClientConnection::new(cfg, name.clone()).unwrap();
        let mut tcp = TcpStream::connect(("127.0.0.1", SP)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        {
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let _ = tls.write_all(b"GET / HTTP/1.1\r\n\r\n");
            let _ = tls.read(&mut [0u8; 1]);
        }
        assert!(
            conn.protocol_version().is_none(),
            "TLS 1.3-only client should be refused"
        );
    }

    // Sixteen half-open handshakes fill this source's slots: the seventeenth is
    // dropped at accept. Once the idle timeout cuts them, the slots are back.
    {
        let held: Vec<TcpStream> = (0..16)
            .map(|_| TcpStream::connect(("127.0.0.1", SP)).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        let mut extra = TcpStream::connect(("127.0.0.1", SP)).unwrap();
        extra.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let r = extra.read(&mut [0u8; 1]);
        assert!(
            !is_timeout(&r),
            "17th connection should be refused at once, got {r:?}"
        );

        let started = std::time::Instant::now();
        for mut s in held {
            s.set_read_timeout(Some(Duration::from_secs(25))).unwrap();
            let r = s.read(&mut [0u8; 1]);
            assert!(
                !is_timeout(&r),
                "idle handshake should be cut by the server, got {r:?}"
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "cut by the idle timeout, not the deadline"
        );

        let cfg = tls_client::config(&[&rustls::version::TLS12]);
        let mut conn = rustls::ClientConnection::new(cfg, name).unwrap();
        let mut tcp = TcpStream::connect(("127.0.0.1", SP)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut all = Vec::new();
        let _ = tls.read_to_end(&mut all);
        assert!(
            String::from_utf8_lossy(&all).starts_with("HTTP/1.1 200 OK"),
            "slots should be released"
        );
    }
}

/// stdout goes to a pipe nobody reads. Once it fills, the log writer thread is
/// stuck for good; connections must still be served and SIGTERM must still end
/// the process after the shutdown grace, not hang on the writer.
#[cfg(unix)]
#[test]
fn shutdown_is_bounded_when_stdout_is_not_read() {
    const HP: u16 = 18088;
    let mut decoy = start_with("danfoss", HP, &[], std::process::Stdio::piped());
    for _ in 0..600 {
        assert_eq!(
            http(HP, "GET", "/nope", None).0,
            404,
            "served while the writer is blocked"
        );
    }
    let path = decoy.log_path.clone();
    let count = || std::fs::read_to_string(&path).unwrap_or_default().lines().count();
    let a = count();
    std::thread::sleep(Duration::from_millis(500));
    let b = count();
    assert!(
        a == b && b < 600,
        "writer should be stuck on the full pipe, got {a} then {b} lines"
    );

    let pid = decoy.child.id().to_string();
    let started = std::time::Instant::now();
    let sent = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -TERM should reach the decoy");
    let exited = loop {
        if decoy.child.try_wait().ok().flatten().is_some() {
            break true;
        }
        if started.elapsed() > Duration::from_secs(6) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    assert!(
        exited,
        "process should exit after SIGTERM even with stdout blocked"
    );
    assert!(
        took >= Duration::from_millis(1500) && took < Duration::from_secs(5),
        "exit should wait out the 2 s grace and no longer, took {took:?}"
    );
}

#[test]
fn modbus_half_frame_is_cut_by_the_idle_timeout() {
    const HP: u16 = 18086;
    const MP: u16 = 15021;
    let _decoy = start("danfoss", HP, &[("MODBUS_PORT", MP.to_string().as_str())]);
    wait_port(("127.0.0.1", MP));
    let mut s = TcpStream::connect(("127.0.0.1", MP)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(25))).unwrap();
    // A complete MBAP header announcing a 5-byte PDU that never arrives.
    s.write_all(&[0, 1, 0, 0, 0, 6, 1]).unwrap();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 8];
    let got = s.read(&mut buf);
    assert!(
        matches!(got, Ok(0)),
        "server should close the half-sent frame, got {got:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "closed by the idle timeout, not the deadline"
    );
}

#[test]
fn identity_is_per_deployment() {
    // Two instances with different seeds get different identities. Certificate
    // subjects are deliberately not compared: they are the model's, shared by
    // every unit of a persona (keys and validity differ; see tls.rs).
    let a = start_identity("seed-a", 18100);
    let b = start_identity("seed-b", 18101);
    assert_ne!(a.0, b.0, "store names should differ across deployments");
    assert_ne!(a.1, b.1, "MAC addresses should differ across deployments");
    assert!(!a.1.is_empty(), "start event should carry the MAC");
}

fn start_identity(seed: &str, port: u16) -> (String, String) {
    let dir = std::env::temp_dir().join(format!("fridgep0t-id-{seed}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("id.jsonl");
    let _ = std::fs::remove_file(&log_path);
    let mut child = Command::new(bin())
        .env("PERSONA", "danfoss")
        .env("BIND", "127.0.0.1")
        .env("HTTP_PORT", port.to_string())
        .env("LOG_PATH", &log_path)
        .env("IDENTITY_SEED", seed)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait_port(("127.0.0.1", port));
    std::thread::sleep(Duration::from_millis(200));
    let ev = events(&log_path);
    let _ = child.kill();
    let _ = child.wait();
    let start = ev.iter().find(|e| e["event"] == "start").expect("start event");
    (
        start["store_name"].as_str().unwrap_or("").to_string(),
        start["mac"].as_str().unwrap_or("").to_string(),
    )
}

fn exploit_seen(ev: &[Value], needle: &str) -> bool {
    ev.iter().any(|e| {
        e.get("exploit")
            .and_then(Value::as_str)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    })
}

fn event_seen(ev: &[Value], name: &str) -> bool {
    ev.iter().any(|e| e["event"] == name)
}

fn login_granted(ev: &[Value]) -> bool {
    ev.iter()
        .any(|e| e["event"] == "login_attempt" && e.get("granted") == Some(&Value::Bool(true)))
}

fn defrost_seen(ev: &[Value]) -> bool {
    ev.iter().any(|e| e.get("defrost") == Some(&Value::Bool(true)))
}

/// A rustls client that trusts any certificate: the decoy's is self-signed by design.
mod tls_client {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    struct TrustAll(rustls::crypto::CryptoProvider);

    impl ServerCertVerifier for TrustAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    pub fn config(versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<rustls::ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAll(provider)))
            .with_no_client_auth();
        Arc::new(cfg)
    }
}
