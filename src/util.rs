//! Small shared helpers used by several persona modules.

use rand::Rng;
use std::collections::HashMap;
use std::time::Duration;

/// Outcome of a login handler: the body to send, after a human-like delay.
pub struct LoginResult {
    pub body: String,
    pub delay: Duration,
}

impl LoginResult {
    pub fn new(body: String) -> LoginResult {
        LoginResult {
            body,
            delay: login_delay(),
        }
    }
}

/// Real units take a noticeable moment to answer a login; an instant reply is a tell.
pub fn login_delay() -> Duration {
    Duration::from_secs_f64(rand::thread_rng().gen_range(0.6..1.4))
}

/// Parse an `application/x-www-form-urlencoded` body into a map.
pub fn parse_form(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let Some(k) = kv.next() {
            let v = kv.next().unwrap_or("");
            map.insert(url_decode(k), url_decode(v));
        }
    }
    map
}

/// Percent-decode a form field (also turning `+` into space).
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Escape text for inclusion in HTML.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Decode a standard base64 string (as used in HTTP Basic auth). Returns the
/// decoded bytes, or None on malformed input.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let s: Vec<u8> = s.into_iter().take_while(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in &s {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Parse an HTTP Basic Authorization header value ("Basic <b64>") into
/// (username, password).
pub fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = base64_decode(b64.trim())?;
    let text = String::from_utf8_lossy(&decoded);
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_handles_plus_percent_and_junk() {
        assert_eq!(url_decode("a+b%20c%2Fd"), "a b c/d");
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz"), "%zz");
        assert_eq!(url_decode("%ff"), "\u{fffd}");
    }

    #[test]
    fn parse_form_splits_pairs() {
        let f = parse_form("user=Admin&password=p%40ss&flag");
        assert_eq!(f.get("user").map(String::as_str), Some("Admin"));
        assert_eq!(f.get("password").map(String::as_str), Some("p@ss"));
        assert_eq!(f.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn basic_auth_round_trip() {
        assert_eq!(
            parse_basic_auth("Basic aHR0cGFkbWluOmZodHRwYWRtaW4="),
            Some(("httpadmin".to_string(), "fhttpadmin".to_string()))
        );
        assert_eq!(parse_basic_auth("Bearer x"), None);
        assert_eq!(parse_basic_auth("Basic !!!"), None);
        assert_eq!(parse_basic_auth("Basic bm9jb2xvbg=="), None);
    }

    #[test]
    fn login_delay_is_within_the_human_band() {
        let d = login_delay();
        assert!(d >= Duration::from_millis(600) && d < Duration::from_millis(1400));
    }
}
