//! Carel pCOWeb persona.
//!
//! Good fidelity, anchored to public documentation:
//!   - the pCOWeb embedded web server is thttpd (Carel pCOWeb user manual);
//!   - web access is HTTP Basic auth against the card's .htpasswd;
//!   - factory accounts are documented (manual sections 9.2.1 / 9.7.2) and
//!     republished in advisory RT-SA-2019-013: httpadmin/fhttpadmin, admin/fadmin,
//!     carel/fcarel, guest/fguest, root/froot;
//!   - /config/pw_changeusers.html discloses stored passwords in cleartext
//!     (RT-SA-2019-013; related to CVE-2019-13553).
//!
//! The page markup is our own; the error pages and the response header set
//! are thttpd's (see `thttpd_error` and `reply()` in server.rs), taken from the
//! source of the release the default Server header names. Override that header
//! with SERVER_HEADER to match a unit you have observed.

use crate::config::Config;
use crate::fields;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::util::{html_escape, parse_basic_auth};
use std::net::SocketAddr;

/// Documented Carel pCOWeb factory accounts. All "succeed": we want to see what
/// an attacker does with access, and these are public anyway.
const FACTORY_LOGINS: &[(&str, &str)] = &[
    ("httpadmin", "fhttpadmin"),
    ("admin", "fadmin"),
    ("carel", "fcarel"),
    ("guest", "fguest"),
    ("root", "froot"),
];

pub struct Carel {
    pub demo_page: String,
    firmware: String,
    mac: String,
}

impl Carel {
    pub fn new(_cfg: &Config, id: &Identity) -> Carel {
        Carel {
            demo_page: build_demo_page(&id.firmware, &id.mac),
            firmware: id.firmware.clone(),
            mac: id.mac.clone(),
        }
    }

    fn is_factory(user: &str, pass: &str) -> bool {
        FACTORY_LOGINS.iter().any(|(u, p)| *u == user && *p == pass)
    }

    /// Handle a request to a /config/ path, which on a real unit is Basic-auth
    /// protected. Returns the response body and status, logging the attempt.
    /// `None` means: send a 401 challenge.
    pub fn config_request(
        &self,
        log: &Logger,
        src: SocketAddr,
        proto: &str,
        path: &str,
        auth: Option<&str>,
    ) -> Option<(u16, String)> {
        let creds = auth.and_then(parse_basic_auth);
        let granted = creds
            .as_ref()
            .map(|(u, p)| Self::is_factory(u, p))
            .unwrap_or(false);

        if let Some((u, p)) = &creds {
            log.log(
                proto,
                src,
                "login_attempt",
                fields! { "username" => u, "password" => p, "granted" => granted, "scheme" => "basic" },
            );
        }
        if !granted {
            return None; // caller sends 401
        }

        // The documented cleartext-credential disclosure page.
        if path == "/config/pw_changeusers.html" {
            log.log(
                proto,
                src,
                "control",
                fields! { "action" => "credential_disclosure", "path" => path, "exploit" => "CVE-2019-13553 cleartext credentials" },
            );
            let rows: String = FACTORY_LOGINS
                .iter()
                .map(|(u, p)| format!("<tr><td>{u}</td><td>{p}</td></tr>"))
                .collect::<Vec<_>>()
                .concat();
            let body = format!(
                "<html><head><title>pCOWeb - users</title></head><body>\
                 <h3>User passwords</h3><table border=\"1\"><tr><th>user</th><th>password</th></tr>\
                 {rows}</table></body></html>"
            );
            return Some((200, body));
        }

        // Any other authenticated config page: a minimal, plausible stub.
        let body = format!(
            "<html><head><title>pCOWeb - config</title></head><body>\
             <h3>pCOWeb configuration</h3><p>MAC {}</p><p>App {}</p></body></html>",
            html_escape(&self.mac),
            html_escape(&self.firmware)
        );
        Some((200, body))
    }

    pub fn basic_realm(&self) -> &'static str {
        "pCOWeb"
    }
}

/// thttpd's built-in error page, which is what scanners key on. Layout and
/// wording are those of `send_response()` and the `err…form` strings in
/// libhttpd.c of thttpd 2.25b (Jef Poskanzer, BSD licence; acme.com), the
/// release our default Server header names. `arg` is what thttpd puts in the
/// sentence: the URL for 401 and 404, the method for 501. Like thttpd's
/// `defang()` it escapes only `<` and `>`, then cuts to 80 bytes (`%.80s`).
/// A pCOWeb with its own `errors/errNNN.html` files would answer differently;
/// none is publicly documented.
pub fn thttpd_error(status: u16, reason: &str, arg: &str, server: &str) -> String {
    let arg: String = arg
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .chars()
        .take(80)
        .collect();
    let text = match status {
        401 => format!("Authorization required for the URL '{arg}'."),
        404 => format!("The requested URL '{arg}' was not found on this server."),
        501 => format!("The requested method '{arg}' is not implemented by this server."),
        _ => "Your request has bad syntax or is inherently impossible to satisfy.".to_string(),
    };
    format!(
        "<HTML>\n<HEAD><TITLE>{status} {reason}</TITLE></HEAD>\n\
         <BODY BGCOLOR=\"#cc9999\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
         <H2>{status} {reason}</H2>\n{text}\n<HR>\n\
         <ADDRESS><A HREF=\"http://www.acme.com/software/thttpd/\">{server}</A></ADDRESS>\n\
         </BODY>\n</HTML>\n"
    )
}

/// Our own pCOWeb demo/landing page (pw_demo.html equivalent).
fn build_demo_page(firmware: &str, mac: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>pCOWeb</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{margin:0;font-family:Verdana,Arial,sans-serif;font-size:12px;background:#ffffff;color:#000}}
.bar{{background:#004b87;color:#fff;padding:8px 12px;font-size:15px;font-weight:bold}}
.bar span{{color:#e30613}}
table{{border-collapse:collapse;margin:16px}}
td,th{{border:1px solid #999;padding:4px 10px;text-align:left}}
th{{background:#e8edf2}}
.note{{margin:16px;color:#555}}</style></head>
<body><div class="bar"><span>CAREL</span> pCOWeb</div>
<table>
<tr><th>Parameter</th><th>Value</th></tr>
<tr><td>Application</td><td>{firmware}</td></tr>
<tr><td>MAC address</td><td>{mac}</td></tr>
<tr><td>Status</td><td>Running</td></tr>
</table>
<p class="note">Configuration requires authentication (/config/).</p>
</body></html>"#,
        firmware = html_escape(firmware),
        mac = html_escape(mac)
    )
}
