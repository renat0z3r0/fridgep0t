//! Eliwell TelevisGo persona.
//!
//! Good fidelity, anchored to the TelevisGo user manual:
//!   - login screen with a plant name, a language selector and a "Save this
//!     information" checkbox;
//!   - default account User "Administrator", Password "0";
//!   - welcome page reports "Eliwell Controls", a software version (e.g. 5.0.0.0),
//!     an O.S. version and a boot-loader version;
//!   - the product runs on MS Windows (10 IoT), so the web server is not an
//!     embedded Linux one.
//!
//! The markup is our own. The Server header is left to SERVER_HEADER (empty by
//! default) because we have no reliable public value for the TelevisGo server.

use crate::config::Config;
use crate::fields;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::state::Sessions;
use crate::util::{parse_form, LoginResult};
use std::net::SocketAddr;

/// Documented default account. Password "0" (zero), per the manual.
const WEAK_LOGINS: &[(&str, &str)] = &[("Administrator", "0"), ("Administrator", "")];

pub struct Eliwell {
    pub login_page: String,
    firmware: String,
    plant: String,
}

impl Eliwell {
    pub fn new(_cfg: &Config, id: &Identity) -> Eliwell {
        Eliwell {
            login_page: build_login_page(&id.store_name, &id.firmware),
            firmware: id.firmware.clone(),
            plant: id.store_name.clone(),
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
            .or_else(|| form.get("j_username"))
            .cloned()
            .unwrap_or_default()
            .chars()
            .take(64)
            .collect();
        let password = form
            .get("password")
            .or_else(|| form.get("j_password"))
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
            serde_json::json!({ "result": "ok", "token": sessions.new_token(), "role": "Administrator" })
                .to_string()
        } else {
            serde_json::json!({ "result": "error" }).to_string()
        };
        LoginResult::new(body)
    }

    /// Welcome/version payload, as the post-login page exposes.
    pub fn welcome(&self) -> String {
        serde_json::json!({
            "product": "TelevisGo",
            "vendor": "Eliwell Controls",
            "software_version": self.firmware,
            "plant": self.plant,
        })
        .to_string()
    }
}

/// Our own TelevisGo-style login page.
fn build_login_page(plant: &str, firmware: &str) -> String {
    let plant = crate::util::html_escape(plant);
    let firmware = crate::util::html_escape(firmware);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TelevisGo</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{margin:0;font-family:"Segoe UI",Tahoma,Arial,sans-serif;background:#eef1f4;color:#222}}
#top{{background:#0a4d8c;color:#fff;padding:10px 16px;font-size:16px}}
#status{{background:#dfe6ee;color:#334;padding:6px 16px;font-size:12px}}
#box{{width:340px;margin:70px auto;background:#fff;border:1px solid #c3ccd6;padding:26px}}
#box h2{{margin:0 0 4px;font-size:18px;color:#0a4d8c}}
#plant{{font-size:12px;color:#667;margin-bottom:18px}}
label{{display:block;font-size:12px;margin:10px 0 3px;color:#445}}
input[type=text],input[type=password],select{{box-sizing:border-box;width:100%;height:34px;padding:5px 9px;border:1px solid #c3ccd6;font-size:14px}}
.row{{margin-top:12px;font-size:12px}}
button{{margin-top:18px;width:100%;height:36px;border:0;background:#0a4d8c;color:#fff;font-weight:bold;cursor:pointer}}
#err{{color:#c0392b;font-size:13px;min-height:16px;margin-top:10px}}
#ver{{margin-top:16px;font-size:11px;color:#8a949d;text-align:center}}</style></head>
<body><div id="top">TelevisGo</div>
<div id="status">Plant: {plant} &nbsp;|&nbsp; Data acquisition: Running &nbsp;|&nbsp; Alarms: &mdash;</div>
<div id="box"><h2>Login</h2><div id="plant">{plant}</div>
<form id="f" autocomplete="off">
<label for="u">User name</label><input type="text" id="u" value="Administrator">
<label for="p">Password</label><input type="password" id="p">
<label for="lang">User interface language</label>
<select id="lang"><option>English</option><option>Italiano</option><option>Fran&ccedil;ais</option><option>Deutsch</option><option>Espa&ntilde;ol</option></select>
<div class="row"><label><input type="checkbox" id="save"> Save this information</label></div>
<button type="submit">Login</button><div id="err"></div></form>
<div id="ver">Eliwell Controls &mdash; Software version {firmware}</div></div>
<script>
function enc(s){{return encodeURIComponent(s)}}
document.getElementById('f').onsubmit=function(ev){{ev.preventDefault();
var b='user='+enc(document.getElementById('u').value)+'&password='+enc(document.getElementById('p').value);
fetch('login',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:b}})
.then(function(r){{return r.json()}}).then(function(j){{if(j.result!=='ok'){{document.getElementById('err').textContent='Wrong user name or password'}}}})}};
</script></body></html>"#
    )
}
