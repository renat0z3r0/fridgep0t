//! Danfoss AK-SC 355 persona.
//!
//! Deliberately shallow. We do not have a copy of the real AK-SC 355 web
//! interface, so this persona is anchored only to what is publicly documented:
//!
//!   - front-end firmware "3.091 or higher" (see Danfoss AK-EM 800 guide);
//!   - a login screen with a "Forgot Credentials" -> "Reset Password" flow that
//!     returns the unit's MAC address and a reset code to quote to Danfoss
//!     support (documented in Danfoss "supporting supermarkets" material);
//!   - the AK-SM/AK-SC family's documented default accounts.
//!
//! The markup is our own. The goal is to catch scanners that hunt specifically
//! for AK-SC 355 units (by title, the reset flow, the firmware band), not to
//! sustain deep interaction. For a deployment you care about, capture a real
//! unit's pages and replace this. The Server header is configurable and empty by
//! default, because we have no reliable public value for the legacy web server.

use crate::config::Config;
use crate::fields;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::state::Sessions;
use crate::util::{parse_form, LoginResult};
use rand::Rng;
use std::net::SocketAddr;

/// Documented default accounts for the Danfoss web front-ends. All log in; we
/// want to see what an attacker does next, not to keep them out.
const WEAK_LOGINS: &[(&str, &str)] = &[
    ("admin", "danfoss"),
    ("administrator", "danfoss"),
    ("user", "danfoss"),
    ("guest", "danfoss"),
    ("Supervisor", "12345"),
];

pub struct Aksc355 {
    pub login_page: String,
    mac: String,
}

impl Aksc355 {
    pub fn new(_cfg: &Config, id: &Identity) -> Aksc355 {
        Aksc355 {
            login_page: build_login_page(&id.hostname, &id.firmware),
            mac: id.mac.clone(),
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
            .get("user")
            .or_else(|| form.get("username"))
            .cloned()
            .unwrap_or_default()
            .chars()
            .take(64)
            .collect();
        let password = form
            .get("password")
            .or_else(|| form.get("pass"))
            .cloned()
            .unwrap_or_default();

        let granted = WEAK_LOGINS
            .iter()
            .any(|(u, p)| u.eq_ignore_ascii_case(&user) && *p == password);

        log.log(
            proto,
            src,
            "login_attempt",
            fields! { "username" => user, "password" => password, "granted" => granted },
        );

        let body = if granted {
            serde_json::json!({ "status": "ok", "token": sessions.new_token() }).to_string()
        } else {
            serde_json::json!({ "status": "fail" }).to_string()
        };
        LoginResult::new(body)
    }

    /// The documented "Forgot Credentials -> Reset Password" disclosure: the unit
    /// shows its MAC address and a reset code. We log the probe as recon; the MAC
    /// is this deployment's generated one, and the code is random per request.
    pub fn reset(&self, log: &Logger, src: SocketAddr, proto: &str) -> String {
        let code: String = {
            let mut rng = rand::thread_rng();
            (0..8)
                .map(|_| {
                    std::char::from_digit(rng.gen_range(0..16), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase()
                })
                .collect()
        };
        log.log(
            proto,
            src,
            "control",
            fields! { "action" => "forgot_credentials", "disclosed_mac" => self.mac.clone() },
        );
        serde_json::json!({ "mac": self.mac, "code": code, "message": "Call Danfoss monitoring with the MAC and code." }).to_string()
    }
}

/// Our own AK-SC 355-style login page. Features the documented reset flow and the
/// firmware string, so the page and any API agree.
fn build_login_page(hostname: &str, firmware: &str) -> String {
    let hostname = crate::util::html_escape(hostname);
    let firmware = crate::util::html_escape(firmware); // FIRMWARE is the operator's free text
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AK-SC 355</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{margin:0;font-family:Arial,Helvetica,sans-serif;background:#d8dde2;color:#1a1a1a}}
#wrap{{width:360px;margin:72px auto;background:#fff;border:1px solid #b9c0c7;border-top:4px solid #e2000f}}
#hd{{background:#2b2f33;color:#fff;padding:12px 16px;font-size:15px}}
#hd span{{color:#e2000f;font-weight:bold}}
#bd{{padding:22px 24px}}
#sys{{font-size:12px;color:#5c6670;margin-bottom:16px}}
input{{box-sizing:border-box;width:100%;height:36px;margin:0 0 12px;padding:6px 10px;border:1px solid #b9c0c7;font-size:14px}}
button{{height:36px;padding:0 18px;border:0;background:#e2000f;color:#fff;font-weight:bold;cursor:pointer}}
#err{{color:#e2000f;font-size:13px;min-height:16px;margin-top:10px}}
#forgot{{display:block;margin-top:14px;font-size:12px;color:#36506e;cursor:pointer}}
#reset{{display:none;margin-top:14px;padding:12px;background:#f3f5f7;border:1px solid #b9c0c7;font-size:13px}}
#reset b{{font-family:monospace}}
#ft{{padding:10px 16px;font-size:11px;color:#8a949d;border-top:1px solid #e2e6ea}}</style></head>
<body><div id="wrap">
<div id="hd"><span>Danfoss</span> AK-SC 355</div>
<div id="bd"><div id="sys">{hostname}</div>
<form id="f" autocomplete="off">
<input type="text" id="u" placeholder="User" autofocus>
<input type="password" id="p" placeholder="Password">
<button type="submit">Log in</button><div id="err"></div></form>
<span id="forgot">Forgot Credentials</span>
<div id="reset"></div></div>
<div id="ft">Front end {firmware}</div></div>
<script>
function enc(s){{return encodeURIComponent(s)}}
document.getElementById('f').onsubmit=function(ev){{ev.preventDefault();
var b='action=login&user='+enc(document.getElementById('u').value)+'&password='+enc(document.getElementById('p').value);
fetch('cgi-bin/login.cgi',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:b}})
.then(function(r){{return r.json()}}).then(function(j){{if(j.status!=='ok'){{document.getElementById('err').textContent='Login failed'}}}})}};
document.getElementById('forgot').onclick=function(){{
fetch('cgi-bin/reset.cgi',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:'action=reset'}})
.then(function(r){{return r.json()}}).then(function(j){{var d=document.getElementById('reset');
d.style.display='block';d.innerHTML='MAC <b>'+j.mac+'</b><br>Reset code <b>'+j.code+'</b><br>'+j.message}})}};
</script></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_supplied_values_are_escaped_in_the_page() {
        let page = build_login_page("AKSC355-0001", "3.091<script>x</script>");
        assert!(
            !page.contains("<script>x"),
            "FIRMWARE must not reach the page raw"
        );
        assert!(page.contains("3.091&lt;script&gt;"));
    }
}
