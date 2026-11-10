//! Resource Data Management (RDM) Data Manager persona.
//!
//! Medium fidelity. Anchored to public reporting:
//!   - the default login password is "1234" (Safety Detectives; Cooling Post),
//!     frequently left unchanged; many units expose the interface with no auth
//!     until "Force CGI login" is enabled;
//!   - the web application is CGI-based (CVE-2015-6468 CSRF against the Data
//!     Manager; plaintext passwords were found in page source).
//!
//! We do not have a reliable public value for the Data Manager's Server header
//! or exact page bytes, so the Server header is left to SERVER_HEADER (empty by
//! default) and the markup is our own, deliberately plain. For a real deployment,
//! capture a reference page and replace it.

use crate::config::Config;
use crate::fields;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::state::{Registers, Sessions, CASE_NAMES};
use crate::util::{parse_form, LoginResult};
use std::net::SocketAddr;

/// Documented default. Username is often blank or a site name; accept a small set.
const WEAK_LOGINS: &[(&str, &str)] = &[("", "1234"), ("admin", "1234"), ("user", "1234")];

pub struct Rdm {
    pub login_page: String,
    firmware: String,
}

impl Rdm {
    pub fn new(_cfg: &Config, id: &Identity) -> Rdm {
        Rdm {
            login_page: build_login_page(&id.store_name, &id.firmware),
            firmware: id.firmware.clone(),
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
            .or_else(|| form.get("pin"))
            .cloned()
            .unwrap_or_default();

        let granted = WEAK_LOGINS.iter().any(|(u, p)| *u == user && *p == password);

        log.log(
            proto,
            src,
            "login_attempt",
            fields! { "username" => user, "password" => password, "granted" => granted },
        );

        let body = if granted {
            serde_json::json!({ "ok": true, "sid": sessions.new_token() }).to_string()
        } else {
            serde_json::json!({ "ok": false }).to_string()
        };
        LoginResult::new(body)
    }

    /// Case status as the dashboard CGI would return it.
    pub fn status(&self, regs: &Registers) -> String {
        let cases: Vec<serde_json::Value> = regs
            .case_status()
            .iter()
            .enumerate()
            .map(|(n, c)| {
                serde_json::json!({
                    "name": CASE_NAMES[n],
                    "temp": c.temp_tenths as f64 / 10.0,
                    "setpoint": c.setpoint_tenths as f64 / 10.0,
                    "defrost": c.defrosting,
                })
            })
            .collect();
        serde_json::json!({ "controller": "Data Manager", "version": self.firmware, "cases": cases })
            .to_string()
    }
}

/// Our own Data Manager-style login page. Deliberately plain (see module note).
fn build_login_page(site: &str, firmware: &str) -> String {
    let site = crate::util::html_escape(site);
    let firmware = crate::util::html_escape(firmware);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Data Manager</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{margin:0;font-family:Arial,Helvetica,sans-serif;background:#2d3137;color:#e8eaed}}
#hd{{background:#1b1e22;padding:12px 16px;font-size:16px;color:#fff;border-bottom:3px solid #d12e2e}}
#box{{width:320px;margin:80px auto;background:#373c43;border:1px solid #4a515a;padding:24px}}
#box h2{{margin:0 0 16px;font-size:16px;font-weight:normal}}
input{{box-sizing:border-box;width:100%;height:34px;margin:0 0 12px;padding:5px 9px;border:1px solid #4a515a;background:#2d3137;color:#fff}}
button{{width:100%;height:36px;border:0;background:#d12e2e;color:#fff;font-weight:bold;cursor:pointer}}
#err{{color:#ff8a8a;font-size:13px;min-height:16px;margin-top:10px}}
#ft{{margin-top:16px;font-size:11px;color:#8b929b;text-align:center}}</style></head>
<body><div id="hd">Data Manager &mdash; {site}</div>
<div id="box"><h2>Sign in</h2>
<form id="f" autocomplete="off">
<input type="text" id="u" placeholder="User">
<input type="password" id="p" placeholder="Password">
<button type="submit">Log in</button><div id="err"></div></form>
<div id="ft">RDM &middot; v{firmware}</div></div>
<script>
function enc(s){{return encodeURIComponent(s)}}
document.getElementById('f').onsubmit=function(ev){{ev.preventDefault();
var b='user='+enc(document.getElementById('u').value)+'&password='+enc(document.getElementById('p').value);
fetch('cgi-bin/login.cgi',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:b}})
.then(function(r){{return r.json()}}).then(function(j){{if(!j.ok){{document.getElementById('err').textContent='Login failed'}}}})}};
</script></body></html>"#
    )
}
