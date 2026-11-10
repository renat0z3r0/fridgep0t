//! A tiny HTTP/1.1 server loop over a tokio stream.
//!
//! Hand-rolled on purpose: a decoy must control the exact header set and order
//! it emits, which a general HTTP framework hides. We read one request, answer,
//! and close (Danfoss static assets aside), mirroring how the real units behave.
//!
//! What `read_request` accepts, and nothing else:
//!   - a request line of exactly three tokens, version `HTTP/1.0` or `HTTP/1.1`;
//!   - headers up to 16 KiB, each line `token: value` (no bare lines, no space
//!     before the colon, no folding, no bare CR/LF in values); a repeated field
//!     combines into one comma-separated list, except `Host`, which HTTP/1.1
//!     must send exactly once, and `Content-Length`, whose repeats must agree;
//!   - `Content-Length` as a run of digits that fits `usize` and is at most
//!     `max_body`; absent means no body;
//!   - no `Transfer-Encoding`.
//!
//! Anything else is refused, never dispatched: the caller logs `bad_request`,
//! answers the persona's 400 (`Bad`) or 413 (`TooLarge`) page and closes; a
//! request cut short by the client's own EOF (`Truncated`) gets no reply. Bytes
//! after the body stay in the carry-over buffer for the next request, so
//! pipelined requests and arbitrary TCP segmentation both parse the same.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    /// Raw body bytes, exactly as sent: binary uploads must round-trip.
    pub body: Vec<u8>,
    pub raw_line: String,
}

impl Request {
    /// The body as text for the form, XML and JSON parsers and for the log;
    /// invalid UTF-8 becomes U+FFFD here and only here.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// HTTP/1.1 keeps the connection unless the client says `Connection: close`;
    /// HTTP/1.0 closes unless it says `keep-alive`. nginx honours both.
    pub fn wants_keep_alive(&self) -> bool {
        // `Connection` is a comma-separated token list; `close` wins over anything else.
        let tokens: Vec<String> = self
            .headers
            .get("connection")
            .map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
            .unwrap_or_default();
        if tokens.iter().any(|t| t == "close") {
            return false;
        }
        self.version != "HTTP/1.0" || tokens.iter().any(|t| t == "keep-alive")
    }
}

pub enum ReadOutcome {
    Ok(Request),
    /// Malformed request; caller should log bad_request, answer 400 and close.
    Bad(String),
    /// Well-formed, but the declared body is over `max_body`: 413 and close.
    TooLarge(String),
    /// The client closed part-way through a request: log bad_request and close
    /// without a reply, as a server does once its peer has gone.
    Truncated(String),
    /// Connection closed or timed out before a full request.
    Eof,
}

const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Read one request from `stream`. `buf` is the connection's carry-over buffer:
/// bytes that arrive after this request (pipelining) stay in it for the next
/// call instead of being dropped.
pub async fn read_request<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max_body: usize,
) -> std::io::Result<ReadOutcome>
where
    S: AsyncReadExt + Unpin,
{
    let mut tmp = [0u8; 1024];
    // Read until end of headers.
    // The header block (everything before the blank line) may be at most
    // MAX_HEADER_BYTES, checked the same way however the bytes were segmented:
    // once the terminator is seen, by its position; before that, allowing for
    // up to three bytes of a terminator still to come.
    let header_end = loop {
        if let Some(pos) = find_double_crlf(buf) {
            if pos > MAX_HEADER_BYTES {
                return Ok(ReadOutcome::Bad(first_line(buf)));
            }
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES + 3 {
            return Ok(ReadOutcome::Bad(first_line(buf)));
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(if buf.is_empty() {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Truncated(first_line(buf))
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    // Exactly three tokens and a version whose framing rules we implement.
    // What counts as a valid method name differs per server (nginx wants upper
    // case, thttpd matches case-blind), so that is the persona's call, not ours.
    let extra = parts.next().is_some();
    if method.is_empty() || path.is_empty() || extra || !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return Ok(ReadOutcome::Bad(request_line));
    }

    // Repeated fields combine into one comma-separated list (RFC 7230 §3.2.2),
    // so a second `Connection:` cannot hide a `close` and a second
    // `Content-Length:` is seen rather than silently replacing the first.
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut content_lengths: Vec<String> = Vec::new();
    let mut hosts = 0u32;
    for line in lines {
        // `token ":" value` (RFC 7230 §3.2): a line without a colon, an empty or
        // padded name, or a bare CR/LF inside the value is not a header line.
        let bad = || Ok(ReadOutcome::Bad(format!("{request_line} [malformed header]")));
        let Some((name, value)) = line.split_once(':') else {
            return bad();
        };
        if !is_token(name) || value.contains(['\r', '\n']) {
            return bad();
        }
        let (k, v) = (name.to_ascii_lowercase(), value.trim().to_string());
        if k == "content-length" {
            content_lengths.push(v.clone());
        }
        if k == "host" {
            hosts += 1;
        }
        match headers.entry(k) {
            Entry::Occupied(mut e) => {
                e.get_mut().push_str(", ");
                e.get_mut().push_str(&v);
            }
            Entry::Vacant(e) => {
                e.insert(v);
            }
        }
    }
    if version == "HTTP/1.1" && hosts == 0 {
        return Ok(ReadOutcome::Bad(format!("{request_line} [missing host]")));
    }
    if hosts > 1 {
        return Ok(ReadOutcome::Bad(format!("{request_line} [duplicate host]")));
    }
    if headers.contains_key("transfer-encoding") {
        return Ok(ReadOutcome::Bad(format!(
            "{request_line} [transfer-encoding unsupported]"
        )));
    }
    let declared = match content_lengths.first() {
        None => 0,
        Some(first) => {
            let well_formed = !first.is_empty()
                && first.bytes().all(|b| b.is_ascii_digit())
                && content_lengths.iter().all(|v| v == first);
            match first.parse::<usize>() {
                Ok(n) if well_formed => n,
                _ => {
                    let seen = content_lengths.join(",");
                    return Ok(ReadOutcome::Bad(format!(
                        "{request_line} [bad content-length {seen:?}]"
                    )));
                }
            }
        }
    };
    // A declared length over `max_body` is refused outright: clipping it would
    // leave its tail in the buffer to be parsed as the next request.
    if declared > max_body {
        return Ok(ReadOutcome::TooLarge(format!(
            "{request_line} [body {declared} > {max_body}]"
        )));
    }
    let body_start = header_end + 4;
    while buf.len() < body_start + declared {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            // EOF before the declared body: never dispatch a partial command.
            let got = buf.len() - body_start;
            return Ok(ReadOutcome::Truncated(format!(
                "{request_line} [incomplete body {got}/{declared}]"
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_end = body_start + declared;
    let body = buf[body_start..body_end].to_vec();
    buf.drain(..body_end);

    Ok(ReadOutcome::Ok(Request {
        method,
        path,
        version,
        headers,
        body,
        raw_line: request_line,
    }))
}

/// RFC 7230 token: one or more tchar, so never empty and never padded.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn first_line(buf: &[u8]) -> String {
    let end = buf
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end.min(256)]).into_owned()
}

/// A response with explicit, ordered headers.
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Server header value, written first; empty means none is sent.
    pub server: String,
    pub close: bool,
    pub head_only: bool,
    /// Protocol version on the status line: thttpd echoes the request's.
    pub version: &'static str,
}

impl Response {
    pub async fn write<S>(self, stream: &mut S) -> std::io::Result<()>
    where
        S: AsyncWriteExt + Unpin,
    {
        let mut out = format!("{} {} {}\r\n", self.version, self.status, self.reason).into_bytes();
        let push = |name: &str, value: &str, out: &mut Vec<u8>| {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        };
        if !self.server.is_empty() {
            push("Server", &self.server, &mut out);
        }
        for (k, v) in &self.headers {
            push(k, v, &mut out);
        }
        out.extend_from_slice(b"\r\n");
        if !self.head_only {
            out.extend_from_slice(&self.body);
        }
        stream.write_all(&out).await?;
        stream.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(version: &str, conn: Option<&str>) -> Request {
        let mut headers = HashMap::new();
        if let Some(c) = conn {
            headers.insert("connection".to_string(), c.to_string());
        }
        Request {
            method: "GET".into(),
            path: "/".into(),
            version: version.into(),
            headers,
            body: Vec::new(),
            raw_line: String::new(),
        }
    }

    async fn parse(raw: &[u8], max_body: usize) -> ReadOutcome {
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        read_request(&mut cursor, &mut Vec::new(), max_body)
            .await
            .unwrap()
    }

    #[test]
    fn keep_alive_follows_the_connection_tokens() {
        assert!(req("HTTP/1.1", None).wants_keep_alive());
        assert!(!req("HTTP/1.1", Some("close")).wants_keep_alive());
        assert!(!req("HTTP/1.1", Some("Close")).wants_keep_alive());
        assert!(!req("HTTP/1.1", Some("keep-alive, close")).wants_keep_alive());
        assert!(req("HTTP/1.1", Some("Upgrade, keep-alive")).wants_keep_alive());
        assert!(!req("HTTP/1.0", None).wants_keep_alive());
        assert!(req("HTTP/1.0", Some("Keep-Alive")).wants_keep_alive());
        assert!(!req("HTTP/1.0", Some("keep-alive, close")).wants_keep_alive());
    }

    #[tokio::test]
    async fn a_complete_request_is_parsed() {
        match parse(
            b"POST /a?b=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
            10,
        )
        .await
        {
            ReadOutcome::Ok(r) => {
                assert_eq!(r.method, "POST");
                assert_eq!(r.path, "/a?b=1");
                assert_eq!(r.headers.get("host").map(String::as_str), Some("h"));
                assert_eq!(r.body, b"hello");
            }
            _ => panic!("expected a parsed request"),
        }
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_not_clipped() {
        // Clipping would leave the tail (here a second request) in the buffer.
        let tail = b"GET / HTTP/1.1\r\n\r\n";
        let mut raw = format!(
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            20 + tail.len()
        )
        .into_bytes();
        raw.extend_from_slice(&[b'x'; 20]);
        raw.extend_from_slice(tail);
        assert!(matches!(parse(&raw, 10).await, ReadOutcome::TooLarge(l) if l.contains("body")));
    }

    #[tokio::test]
    async fn an_incomplete_body_is_never_dispatched() {
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 500\r\n\r\n<cmd action=\"start_defrost\"/>";
        assert!(matches!(parse(raw, 8192).await, ReadOutcome::Truncated(l) if l.contains("incomplete")));
    }

    #[tokio::test]
    async fn malformed_or_conflicting_content_length_is_refused() {
        for cl in [
            "-1",
            "99999999999999999999999",
            "+5",
            "5\r\nContent-Length: 7",
            "",
        ] {
            let raw = format!("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {cl}\r\n\r\nhello, world");
            assert!(
                matches!(parse(raw.as_bytes(), 8192).await, ReadOutcome::Bad(l) if l.contains("content-length")),
                "{cl:?} should be refused"
            );
        }
        // Identical repeats are allowed (RFC 7230 §3.3.2).
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        assert!(matches!(parse(raw, 8192).await, ReadOutcome::Ok(r) if r.body == b"hello"));
    }

    #[tokio::test]
    async fn repeated_connection_headers_combine_and_close_wins() {
        let raw = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n";
        match parse(raw, 10).await {
            ReadOutcome::Ok(r) => {
                assert_eq!(
                    r.headers.get("connection").map(String::as_str),
                    Some("close, keep-alive")
                );
                assert!(!r.wants_keep_alive());
            }
            _ => panic!("expected a parsed request"),
        }
    }

    #[tokio::test]
    async fn chunked_bodies_are_refused() {
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(matches!(parse(raw, 8192).await, ReadOutcome::Bad(l) if l.contains("transfer-encoding")));
    }

    #[tokio::test]
    async fn pipelined_requests_survive_in_the_carry_over_buffer() {
        let raw = b"GET /one HTTP/1.1\r\nHost: h\r\n\r\nGET /two HTTP/1.1\r\nHost: h\r\n\r\n";
        for size in [1, 5, 1024] {
            let mut stream = segments(raw, size);
            let mut buf = Vec::new();
            let first = read_request(&mut stream, &mut buf, 10).await.unwrap();
            let second = read_request(&mut stream, &mut buf, 10).await.unwrap();
            assert!(
                matches!(first, ReadOutcome::Ok(r) if r.path == "/one"),
                "{size}-byte segments"
            );
            assert!(
                matches!(second, ReadOutcome::Ok(r) if r.path == "/two"),
                "{size}-byte segments"
            );
            assert!(matches!(
                read_request(&mut stream, &mut buf, 10).await.unwrap(),
                ReadOutcome::Eof
            ));
        }
    }

    #[tokio::test]
    async fn only_http_1_0_and_1_1_with_three_tokens_and_one_host() {
        assert!(
            matches!(parse(b"GET / HTTP/1.1\r\n\r\n", 10).await, ReadOutcome::Bad(l) if l.contains("host"))
        );
        assert!(matches!(
            parse(b"GET / HTTP/1.0\r\n\r\n", 10).await,
            ReadOutcome::Ok(_)
        ));
        assert!(matches!(
            parse(b"GET / HTTP/2.0\r\n\r\n", 10).await,
            ReadOutcome::Bad(_)
        ));
        assert!(matches!(
            parse(b"GET / HTTP/1.1 extra\r\n\r\n", 10).await,
            ReadOutcome::Bad(_)
        ));
        assert!(matches!(parse(b"GET /\r\n\r\n", 10).await, ReadOutcome::Bad(_)));
        let dup = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
        assert!(matches!(parse(dup, 10).await, ReadOutcome::Bad(l) if l.contains("host")));
    }

    #[tokio::test]
    async fn malformed_header_lines_are_refused() {
        for bad in [
            &b"GET / HTTP/1.1\r\nHost: h\r\nnocolon\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length : 0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\n: novalue\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\r\nX-A: one\r\n continued\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: h\nX-Smuggled: 1\r\n\r\n",
        ] {
            let got = parse(bad, 10).await;
            assert!(
                matches!(&got, ReadOutcome::Bad(l) if l.contains("malformed")),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert!(matches!(
            parse(b"GET / HTTP/1.1\r\nHost: h\r\nX-Ok_1.a: v\r\n\r\n", 10).await,
            ReadOutcome::Ok(_)
        ));
    }

    #[tokio::test]
    async fn tcp_segmentation_does_not_change_the_outcome() {
        let cases: [(&[u8], &str); 6] = [
            (
                b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
                "ok",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n",
                "ok",
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
                "bad",
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello",
                "bad",
            ),
            (b"POST / HTTP/1.1\r\nContent-Length: 500\r\n\r\nshort", "bad"),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                "bad",
            ),
        ];
        for (raw, expected) in cases {
            for size in [1, 2, 3, 7, 64, 1024] {
                let got = read_request(&mut segments(raw, size), &mut Vec::new(), 8192)
                    .await
                    .unwrap();
                assert_eq!(
                    kind(&got),
                    expected,
                    "{:?} in {size}-byte segments",
                    String::from_utf8_lossy(raw)
                );
            }
        }
        // The header limit is exact and independent of segmentation: a header
        // block of MAX_HEADER_BYTES passes, one byte more is refused, either way.
        let prefix = "GET / HTTP/1.1\r\nHost: h\r\nX-Pad: ";
        for (extra, expected) in [(0usize, "ok"), (1, "bad")] {
            let raw = format!(
                "{prefix}{}\r\n\r\n",
                "a".repeat(MAX_HEADER_BYTES - prefix.len() + extra)
            );
            for size in [1, 1000, 1024] {
                let got = read_request(&mut segments(raw.as_bytes(), size), &mut Vec::new(), 8192)
                    .await
                    .unwrap();
                assert_eq!(
                    kind(&got),
                    expected,
                    "header of max+{extra} bytes in {size}-byte segments"
                );
            }
        }
        // The body is intact however the segments fall.
        for size in [1, 4, 9, 1024] {
            let raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world";
            let got = read_request(&mut segments(raw, size), &mut Vec::new(), 8192)
                .await
                .unwrap();
            assert!(
                matches!(got, ReadOutcome::Ok(r) if r.body == b"hello world"),
                "{size}-byte segments"
            );
        }
    }

    /// A stream that hands out the input one TCP-segment-sized piece per read.
    struct Segments(std::collections::VecDeque<Vec<u8>>);

    impl tokio::io::AsyncRead for Segments {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(part) = self.0.pop_front() {
                buf.put_slice(&part);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn segments(raw: &[u8], size: usize) -> Segments {
        Segments(raw.chunks(size).map(|c| c.to_vec()).collect())
    }

    fn kind(o: &ReadOutcome) -> &'static str {
        match o {
            ReadOutcome::Ok(_) => "ok",
            ReadOutcome::Bad(_) | ReadOutcome::TooLarge(_) | ReadOutcome::Truncated(_) => "bad",
            ReadOutcome::Eof => "eof",
        }
    }

    #[tokio::test]
    async fn body_bytes_are_kept_raw_and_text_is_lossy() {
        match parse(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\n\xff\x00\xfe",
            10,
        )
        .await
        {
            ReadOutcome::Ok(r) => {
                assert_eq!(r.body, [0xff, 0x00, 0xfe]);
                assert_eq!(r.text(), "\u{fffd}\0\u{fffd}");
            }
            _ => panic!("expected a parsed request"),
        }
    }

    #[tokio::test]
    async fn garbage_is_a_bad_request() {
        assert!(matches!(
            parse(b"\x16\x03\x01garbage\r\n\r\n", 10).await,
            ReadOutcome::Bad(_)
        ));
    }
}
