//! Dixell/Copeland XWEB EVO persona.
//!
//! The login markup is our own. Element ids and asset paths follow what public
//! scanners record for real XWEB EVO units; the CVE-2021-45420 handling now
//! simulates the file-write/retrieve round trip that public exploit checks
//! (e.g. the Nuclei template) actually verify, instead of returning an empty
//! 200 that any automated tool would see through.

use crate::config::Config;
use crate::fields;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::state::{Registers, Sessions};
use crate::util::{html_escape, parse_form, LoginResult};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Admin/Admin is the documented factory login; the others are common guesses.
const WEAK_LOGINS: &[(&str, &str)] = &[("admin", "Admin"), ("Admin", "Admin"), ("admin", "admin")];
const LOCKOUT_TRIES: usize = 5;
const LOCKOUT_SECONDS: u64 = 300;

/// Public assets the real page references. Served empty so the page does not
/// trail 404s; scanners fingerprint the unit by these paths existing.
pub const SCRIPTS: &[&str] = &[
    "lib/jquery.min.js",
    "lib/jquery.fileDownload.js",
    "lib/dialog-polyfill.js",
    "lib/moment.min.js",
    "lib/plotly.min.js",
    "lib/snapsvg.min.js",
    "lib/jszip.min.js",
    "lib/fullcalendar.js",
    "lib/quantum.bundle.min.js",
    "lib/AdvancedWebSocket.min.js",
    "xweb.js",
    "streammanager.js",
];
pub const STYLES: &[&str] = &["icons.css", "style.min.css", "fullcalendar.css"];

/// Exploit paths from the public CVE-2021-45420 report (Swascan / Exploit-DB).
pub fn exploit_path(path: &str) -> Option<&'static str> {
    Some(match path {
        "/cgi-bin/logo_extra_upload.cgi" => "CVE-2021-45420 file upload",
        "/cgi-bin/cal_save.cgi" => "CVE-2021-45420 file upload",
        "/cgi-bin/lo_utils.cgi" => "CVE-2021-45420 command execution",
        "/cgi-bin/cal_dir.cgi" => "CVE-2021-45420 directory listing",
        _ => return None,
    })
}

pub struct Dixell {
    pub login_page: String,
    /// Failed logins per (source, username): one scanner's wrong guesses must
    /// not lock the factory account for whoever comes next.
    failures: Mutex<HashMap<(IpAddr, String), Vec<Instant>>>,
    /// Files an attacker "wrote" via the upload CGIs, name -> body. Capped.
    uploads: Mutex<HashMap<String, Vec<u8>>>,
}

impl Dixell {
    pub fn new(_cfg: &Config, id: &Identity) -> Dixell {
        Dixell {
            login_page: build_login_page(&id.store_name, &id.firmware, &id.mac),
            failures: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
        }
    }

    pub fn login(
        &self,
        log: &Logger,
        sessions: &Sessions,
        src: SocketAddr,
        proto: &str,
        body: &str,
    ) -> LoginResult {
        let form = parse_form(body);
        let user: String = form
            .get("username")
            .cloned()
            .unwrap_or_default()
            .chars()
            .take(64)
            .collect();
        let password = form.get("password").cloned().unwrap_or_default();
        let mode = form.get("auth_mode").cloned().unwrap_or_default();

        let exploit = if !mode.is_empty() && mode != "standard" && mode != "ldap" {
            Some("CVE-2026-25085 auth_mode bypass (XWEB Pro)")
        } else {
            None
        };

        let now = Instant::now();
        let (granted, locked) = {
            let mut f = self.failures.lock().unwrap();
            let recent = f.entry((src.ip(), user.clone())).or_default();
            recent.retain(|t| now.duration_since(*t) < Duration::from_secs(LOCKOUT_SECONDS));
            let locked = recent.len() >= LOCKOUT_TRIES;
            let granted = !locked && WEAK_LOGINS.iter().any(|(u, p)| *u == user && *p == password);
            if !granted && !locked {
                recent.push(now);
            }
            if f.len() > 10_000 {
                // Over the cap, forget everything except live lockouts: filling
                // the table with junk user names must not lift one's own lock.
                f.retain(|_, tries| {
                    let fresh = |t: &Instant| now.duration_since(*t) < Duration::from_secs(LOCKOUT_SECONDS);
                    tries.len() >= LOCKOUT_TRIES && tries.last().is_some_and(fresh)
                });
            }
            (granted, locked)
        };

        log.log(
            proto,
            src,
            "login_attempt",
            fields! {
                "username" => user, "password" => password, "auth_mode" => mode,
                "granted" => granted, "locked" => locked, "exploit" => exploit,
            },
        );

        let body = if granted {
            serde_json::json!({
                "result": "ok",
                "user": { "username": user, "level": "admin", "sses": sessions.new_token() }
            })
            .to_string()
        } else {
            serde_json::json!({ "result": "error", "code": 401, "locked": locked }).to_string()
        };
        LoginResult::new(body)
    }

    pub fn datachart(
        &self,
        log: &Logger,
        sessions: &Sessions,
        regs: &Registers,
        src: SocketAddr,
        proto: &str,
        body: &str,
    ) -> Option<String> {
        let form = parse_form(body);
        let authed = sessions.valid(form.get("SSES").map(String::as_str).unwrap_or(""));
        log.log(
            proto,
            src,
            "datachart",
            fields! { "session" => authed, "request" => form.get("request").cloned().unwrap_or_default() },
        );
        if !authed {
            return None; // expired session -> login page, as on real units
        }
        let ts = chrono::Utc::now().timestamp();
        let map: serde_json::Map<String, serde_json::Value> = regs
            .case_status()
            .iter()
            .enumerate()
            .map(|(n, c)| {
                (
                    (n + 1).to_string(),
                    serde_json::json!([{ "ts": ts, "rf": 0, "1": (c.temp_tenths as f64 / 10.0) }]),
                )
            })
            .collect();
        Some(serde_json::Value::Object(map).to_string())
    }

    /// CVE-2021-45420: a POST to an upload CGI "writes" a file under /logo/.
    /// We keep the first line (the exploit's chosen filename) and the body, so a
    /// follow-up GET /logo/<name> returns what was uploaded — the exact
    /// write-then-read handshake a public checker verifies. The body is raw
    /// bytes, so a binary probe comes back byte for byte. Nothing touches disk.
    pub fn upload(&self, log: &Logger, src: SocketAddr, proto: &str, path: &str, body: &[u8]) -> String {
        let (first, rest) = match body.iter().position(|&b| b == b'\n') {
            Some(i) => (&body[..i], Some(&body[i + 1..])),
            None => (body, None),
        };
        let first = String::from_utf8_lossy(first);
        let first = first.trim();
        // Accept a sane-looking filename; otherwise synthesise one.
        let name: String = if !first.is_empty()
            && first.len() <= 64
            && first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            first.to_string()
        } else {
            format!("upload_{:08x}.txt", rand::thread_rng().gen::<u32>())
        };
        // With a name line the rest is the file, even when empty; without one
        // the whole body is the file.
        let content = rest.unwrap_or(body);
        {
            let mut up = self.uploads.lock().unwrap();
            if up.len() > 256 {
                up.clear(); // bound memory; this is a decoy, not storage
            }
            up.insert(name.clone(), content.iter().take(8192).copied().collect());
        }
        log.log(
            proto,
            src,
            "control",
            fields! { "action" => "file_write", "path" => path, "stored_as" => format!("/logo/{name}") },
        );
        // Mirror the real CGIs' terse OK so a checker's status match passes.
        "OK\n".to_string()
    }

    /// GET /logo/<name>: return a prior upload if present (exploit result check).
    pub fn fetch_upload(&self, name: &str) -> Option<Vec<u8>> {
        self.uploads.lock().unwrap().get(name).cloned()
    }

    /// GET /cgi-bin/cal_dir.cgi or /logo/ : a directory listing, as the real
    /// unit's misconfiguration exposes. Lists any uploads plus a plausible stub.
    pub fn dir_listing(&self) -> String {
        let up = self.uploads.lock().unwrap();
        let mut rows = String::new();
        rows.push_str("<a href=\"logo_std.png\">logo_std.png</a>\n");
        for name in up.keys() {
            rows.push_str(&format!("<a href=\"{name}\">{name}</a>\n"));
        }
        format!(
            "<html><head><title>Index of /logo</title></head><body>\
             <h1>Index of /logo</h1><pre>{rows}</pre></body></html>"
        )
    }
}

/// Our own XWEB EVO-style login page. What
/// it shows follows a real unit's login page (see FINGERPRINTS.md): software
/// version, plant name, the product name "XWEB 500 EVO", and the MAC as bare
/// upper-case hex. The markup around them is ours.
fn build_login_page(plant: &str, firmware: &str, mac: &str) -> String {
    // STORE_NAME and FIRMWARE are the operator's free text.
    let (plant, firmware) = (html_escape(plant), html_escape(firmware));
    let mac = html_escape(&mac.replace(':', "").to_ascii_uppercase());
    let scripts = SCRIPTS
        .iter()
        .map(|n| format!("<script src=\"js/{n}\"></script>"))
        .collect::<Vec<_>>()
        .concat();
    let page = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XWEB EVO</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="img/icons/icon16.ico"><link rel="stylesheet" href="css/icons.css">
<link rel="stylesheet" href="css/style.min.css"><link rel="stylesheet" href="css/fullcalendar.css">
<style>body{{margin:0;font-family:Arial,Helvetica,sans-serif;background:#1d2733;color:#e6ebf0}}
#login-screen{{width:340px;margin:90px auto;background:#26323f;padding:28px;border-radius:4px}}
#login-logo{{font:bold 26px Arial;letter-spacing:1px;color:#fff;margin-bottom:4px}}
#login-sysname{{color:#9fb0c0;font-size:13px;margin-bottom:22px}}
.input{{width:100%;box-sizing:border-box;margin:0 0 12px;padding:9px;border:1px solid #3b4a5a;background:#1d2733;color:#fff}}
#login-mode,#login-language{{width:100%;margin:0 0 16px;padding:8px;background:#1d2733;color:#fff;border:1px solid #3b4a5a}}
#login-button{{width:100%;padding:10px;border:0;background:#0f7bc0;color:#fff;font-weight:bold;cursor:pointer}}
#login-error{{color:#ff6b6b;font-size:13px;min-height:16px;margin-top:12px}}
#login-date,#login-macaddress{{font-size:11px;color:#71849a;margin-top:6px}}</style></head>
<body><div id="login-screen"><div>{firmware}</div><div id="login-logo">XWEB 500 EVO</div>
<div id="login-sysname">{plant}</div><div id="login-lock"></div><div id="login-alarms"></div>
<form id="login-form" action="javascript:return false;" autocomplete="off">
<input id="login-username" type="text" placeholder="username" class="input" autofocus required>
<input id="login-password" type="password" placeholder="password" class="input" required>
<select id="login-mode"><option value="standard">standard</option><option value="ldap">ldap</option></select>
<select id="login-language"><option>English</option><option>Italiano</option><option>Deutsch</option></select>
<button id="login-button" type="submit">Login</button><div id="login-error"></div></form>
<div id="login-date"></div><div id="login-macaddress">{mac}</div></div>
{scripts}
<script>
document.getElementById('login-date').textContent=new Date().toLocaleString();
document.getElementById('login-form').onsubmit=function(ev){{ev.preventDefault();
function v(id){{return encodeURIComponent(document.getElementById(id).value)}}
var b='action=login&auth_mode='+v('login-mode')+'&username='+v('login-username')+'&password='+v('login-password')+'&initparam=-1';
fetch('cgi-bin/login.lua',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:b}})
.then(function(r){{return r.json()}}).then(function(j){{if(!j.user){{document.getElementById('login-error').textContent=j.locked?'User locked, retry later':'Login failed'}}}})}};
</script></body></html>"#
    );
    // No byte-length padding: the observed unit's page is ~8.2 KiB, but we have
    // no capture of its real content to fill the gap, and a tail of blank lines
    // is a worse tell than a page that is merely shorter.
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_values_are_escaped_in_the_page() {
        let page = build_login_page("Market<script>x</script>", "5.8.8", "00:0a:f6:00:00:01");
        assert!(!page.contains("<script>x"));
        assert!(page.contains("Market&lt;script&gt;"));
    }

    #[test]
    fn the_page_shows_what_a_real_login_page_shows() {
        // Plant name, software version and the MAC as bare upper-case hex.
        let page = build_login_page("Market Nord 0412", "5.8.3", "00:0a:f6:1b:2c:3d");
        for needle in ["Market Nord 0412", "5.8.3", "XWEB 500 EVO", ">000AF61B2C3D<"] {
            assert!(page.contains(needle), "{needle} missing");
        }
        assert!(!page.contains("00:0a:f6"), "no colon-separated MAC on the page");
    }

    #[test]
    fn lockout_is_per_source_not_per_account() {
        let dir = std::env::temp_dir().join(format!("fridgep0t-dixell-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::from_env().unwrap();
        cfg.log_path = dir.join("events.jsonl");
        let (log, sessions) = (Logger::new(&cfg).unwrap(), Sessions::new(&cfg));
        let d = Dixell::new(&cfg, &Identity::generate(&cfg));
        let scanner: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let other: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        let good = "username=Admin&password=Admin";
        for _ in 0..LOCKOUT_TRIES {
            d.login(&log, &sessions, scanner, "http", "username=Admin&password=wrong");
        }
        let locked = d.login(&log, &sessions, scanner, "http", good).body;
        assert!(locked.contains("\"locked\":true"), "{locked}");
        let ok = d.login(&log, &sessions, other, "http", good).body;
        assert!(
            ok.contains("\"result\":\"ok\""),
            "another source is not locked: {ok}"
        );
        // Filling the table with junk user names must not lift one's own lock.
        for i in 0..10_050 {
            let junk = format!("username=u{i}&password=x");
            d.login(&log, &sessions, scanner, "http", &junk);
        }
        let still = d.login(&log, &sessions, scanner, "http", good).body;
        assert!(still.contains("\"locked\":true"), "{still}");
        log.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
