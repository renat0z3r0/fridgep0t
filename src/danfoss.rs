//! Danfoss AK-SM 800A persona.
//!
//! The markup below is our own; it imitates the StoreView login only closely
//! enough to pass a scanner's title/structure checks, and is not copied from
//! the vendor's firmware. Exploit detection follows the public advisories cited
//! in the README.

use crate::config::Config;
use crate::fields;
use crate::http::Request;
use crate::identity::Identity;
use crate::logging::Logger;
use crate::state::{Registers, Sessions, CASE_NAMES};
use crate::util::{html_escape as xml_escape, login_delay};
use chrono::{Datelike, Timelike};
use chrono_tz::Tz;
use regex::Regex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Logins that "succeed", so we can watch what an attacker does next.
/// Supervisor/12345 is the reported AK-SM factory default; the rest are common
/// guesses seen in the wild against these units.
const WEAK_LOGINS: &[(&str, &str)] = &[
    ("supervisor", "12345"),
    ("superviseur", "12345"),
    ("admin", "admin"),
    ("admin", "1234"),
];

pub struct Danfoss {
    pub login_page: String,
    cmd_re: Regex,
    attr_re: Regex,
    device_tz: Tz,
    store_name: String,
    firmware: String,
    mac: String,
}

pub struct XmlOutcome {
    pub body: String,
    /// Artificial login delay to apply (outside the lock), if any.
    pub delay: Option<std::time::Duration>,
}

impl Danfoss {
    pub fn new(cfg: &Config, id: &Identity) -> Danfoss {
        // Firmware string reused in the page and the XML API, so they agree.
        let login_page = build_login_page(&id.firmware);
        Danfoss {
            login_page,
            cmd_re: Regex::new(r"(?s)<cmd\b([^>]{0,2000})>").unwrap(),
            attr_re: Regex::new(r#"([A-Za-z_][\w.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap(),
            device_tz: cfg.device_tz,
            store_name: id.store_name.clone(),
            firmware: id.firmware.clone(),
            mac: id.mac.clone(),
        }
    }

    fn parse_attrs(&self, body: &str) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        if let Some(cmd) = self.cmd_re.captures(body).and_then(|c| c.get(1)) {
            for cap in self.attr_re.captures_iter(cmd.as_str()).take(16) {
                let key: String = cap[1].chars().take(32).collect();
                let quoted = cap.get(2).or_else(|| cap.get(3)).map_or("", |m| m.as_str());
                let val: String = quoted.chars().take(256).collect();
                attrs.entry(key).or_insert(val);
            }
        }
        attrs
    }

    /// The CVE-2025-41450 "code of the day", per the Ironhackers analysis.
    fn code_of_the_day(&self, date: chrono::NaiveDate) -> String {
        let s = format!(
            "{:02}{:02}{:02}{:02}",
            date.month(),
            date.day(),
            date.year() % 100,
            date.month()
        );
        let num = i64::from_str_radix(&s, 16).unwrap_or(0);
        let div = i64::from_str_radix(&format!("{:02}", date.day()), 16)
            .unwrap_or(1)
            .max(1);
        format!("{:05}", (num / div) % 100_000)
    }

    /// Valid codes for yesterday/today/tomorrow in the device's own time zone.
    fn valid_codes(&self) -> Vec<String> {
        let today = chrono::Utc::now().with_timezone(&self.device_tz).date_naive();
        (-1..=1)
            .filter_map(|d| today.checked_add_signed(chrono::Duration::days(d)))
            .map(|date| self.code_of_the_day(date))
            .collect()
    }

    fn exploit_tag(action: &str, attrs: &HashMap<String, String>) -> Option<&'static str> {
        if action == "get_file" && attrs.get("filename").map(|f| f.contains("..")).unwrap_or(false) {
            return Some("CVE-2023-25914 path traversal");
        }
        if action == "load_cert" {
            return Some("CVE-2023-25915 command injection");
        }
        if action == "load_nginx_headers" {
            return Some("CVE-2025-41452 nginx header overwrite");
        }
        if attrs.contains_key("eds_only") || attrs.contains_key("quantum_only") {
            return Some("SM800 code-of-the-day auth bypass");
        }
        None
    }

    pub fn handle_xml(
        &self,
        log: &Logger,
        sessions: &Arc<Sessions>,
        regs: &Registers,
        src: SocketAddr,
        proto: &str,
        req: &Request,
    ) -> XmlOutcome {
        let attrs = self.parse_attrs(&req.text());
        let action = attrs.get("action").cloned().unwrap_or_default();
        let token = req.headers.get("aksm-auth").cloned().unwrap_or_default();
        let mut exploit = Self::exploit_tag(&action, &attrs).map(|s| s.to_string());

        let user = attrs.get("user").cloned().unwrap_or_default();
        let password = attrs
            .get("password")
            .or_else(|| attrs.get("pass"))
            .cloned()
            .unwrap_or_default();
        let is_login = action == "getauth" || attrs.contains_key("user") || attrs.contains_key("pass");

        let mut granted = false;
        if is_login {
            if attrs.contains_key("eds_only") || attrs.contains_key("quantum_only") {
                granted = self.valid_codes().iter().any(|c| c == &password);
                exploit = Some(format!(
                    "CVE-2025-41450 code-of-the-day bypass{}",
                    if granted { ", correct code" } else { "" }
                ));
            } else {
                granted = WEAK_LOGINS
                    .iter()
                    .any(|(u, p)| u.eq_ignore_ascii_case(&user) && *p == password);
            }
        }
        let authed = sessions.valid(&token) || granted;

        log.log(
            proto,
            src,
            "xml_cmd",
            fields! {
                "action" => action,
                "attrs" => attrs,
                "auth_header" => token,
                "session" => authed,
                "exploit" => exploit,
            },
        );

        let mut delay = None;
        if is_login {
            log.log(
                proto,
                src,
                "login_attempt",
                fields! { "username" => user, "password" => password, "granted" => granted },
            );
            delay = Some(login_delay());
        }

        let head = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        let act = xml_escape(&action);

        // read_date_time answers without a session on real units — and now in
        // the device's own time zone, not the container's UTC.
        if action == "read_date_time" {
            let now = chrono::Utc::now().with_timezone(&self.device_tz);
            let body = format!(
                "{head}<resp action=\"read_date_time\" error=\"0\"><year>{}</year><month>{}</month>\
                 <day>{}</day><hour>{}</hour><minute>{}</minute><second>{}</second></resp>",
                now.year(),
                now.month(),
                now.day(),
                now.hour(),
                now.minute(),
                now.second()
            );
            return XmlOutcome { body, delay };
        }

        if action == "getauth" {
            let body = if !granted {
                format!("{head}<resp action=\"getauth\" error=\"0\"><authtype>-1</authtype><accesslevel>255</accesslevel></resp>")
            } else {
                format!(
                    "{head}<resp action=\"getauth\" error=\"0\"><authorization>01-01</authorization>\
                     <authtype>16777215</authtype><access>01-01</access><accesslevel>1</accesslevel>\
                     <strongpassword>1</strongpassword><session_token>{}</session_token></resp>",
                    sessions.new_token()
                )
            };
            return XmlOutcome { body, delay };
        }

        if !authed {
            // 15 = documented "failed in authorization".
            return XmlOutcome {
                body: format!("{head}<resp action=\"{act}\" error=\"15\"/>"),
                delay,
            };
        }

        if action == "read_units" {
            let body = format!(
                "{head}<resp action=\"read_units\" error=\"0\"><store_name>{}</store_name>\
                 <software>{}</software><macaddr>{}</macaddr><port>80</port></resp>",
                xml_escape(&self.store_name),
                xml_escape(&self.firmware),
                xml_escape(&self.mac)
            );
            return XmlOutcome { body, delay };
        }

        if action == "read_devices" {
            let rows: String = regs
                .case_status()
                .iter()
                .enumerate()
                .map(|(n, c)| {
                    format!(
                        "<device node=\"{}\" name=\"{}\" temp=\"{:.1}\" setpoint=\"{:.1}\" defrost=\"{}\"/>",
                        n + 1,
                        CASE_NAMES[n],
                        c.temp_tenths as f64 / 10.0,
                        c.setpoint_tenths as f64 / 10.0,
                        if c.defrosting { 1 } else { 0 }
                    )
                })
                .collect::<Vec<_>>()
                .concat();
            return XmlOutcome {
                body: format!("{head}<resp action=\"read_devices\" error=\"0\">{rows}</resp>"),
                delay,
            };
        }

        // Anything else from a logged-in session is a control attempt.
        let node = attrs.get("node").cloned().unwrap_or_default();
        let defrost = action.to_lowercase().contains("defrost");
        log.log(
            proto,
            src,
            "control",
            fields! { "action" => action, "node" => node, "defrost" => defrost },
        );
        if defrost {
            if let Ok(n) = node.parse::<u16>() {
                if (1..=CASE_NAMES.len() as u16).contains(&n) {
                    regs.write(200 + n - 1, &[1]);
                }
            }
        }
        XmlOutcome {
            body: format!("{head}<resp action=\"{act}\" error=\"0\"/>"),
            delay,
        }
    }
}

/// Our own StoreView-style login page; firmware string is injected so it always
/// matches what the XML API reports.
fn build_login_page(firmware: &str) -> String {
    let firmware = xml_escape(firmware); // FIRMWARE is the operator's free text
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Danfoss StoreView</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{margin:0;font-family:Raleway,"Helvetica Neue",Helvetica,Arial,sans-serif;background:#f0f0f0;color:#000}}
.bar{{background:#e2000f;color:#fff;font-size:15px;padding:12px 16px}}.bar b{{font-style:italic;font-weight:bold;margin-right:8px}}
.sub{{background:#4a4a4a;color:#e6e6e6;font-size:13px;padding:8px 16px}}
.box{{width:380px;margin:80px auto;text-align:center}}
.brand{{color:#e2000f;font:italic bold 72px Georgia,serif;line-height:156px}}
.title{{color:#f00e0e;font:bold 34px sans-serif;margin:30px 0 64px}}
.ver{{font-size:13px;color:#666;margin-bottom:24px}}.ver b{{font-size:17px;color:#000;margin-right:4px}}
input{{display:block;box-sizing:border-box;width:330px;height:40px;margin:7px auto;padding:6px 12px;font-size:14px;font-family:inherit;border:1px solid #ccc;background:#fefefe}}
.signin{{margin-top:28px;background:#323232;color:#fff;font-weight:500;border:0;cursor:pointer}}
.err{{color:#e2000f;font-size:13px;min-height:16px;margin-top:14px}}
table{{width:100%;border-collapse:collapse;background:#fff}}th,td{{text-align:left;padding:7px;border-bottom:1px solid #ddd}}
th{{background:#323a45;color:#fff;font-weight:normal}}td button{{padding:3px 8px;font-size:12px;border:1px solid #bbb;background:#fff;cursor:pointer}}</style></head>
<body><div class="box">
<div class="brand">Danfoss</div>
<div class="title">System Manager 800A</div><div class="ver"><b>Version</b>{firmware}</div>
<form id="f"><input type="text" id="u" placeholder="Username" autocomplete="off">
<input type="password" id="p" placeholder="Password">
<input type="submit" class="signin" value="Sign In">
<div class="err" id="e"></div></form></div>
<script>
function x(s){{return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;')}}
var tok='';
function api(cmd){{return fetch('/html/xml.cgi',{{method:'POST',headers:{{'Content-Type':'text/xml','AKSM-Auth':tok}},body:cmd}}).then(function(r){{return r.text()}})}}
document.getElementById('f').onsubmit=function(ev){{ev.preventDefault();
var b='<cmd action="getauth" user="'+x(document.getElementById('u').value)+'" password="'+x(document.getElementById('p').value)+'" lang="English"/>';
api(b).then(function(t){{var m=/<session_token>([0-9a-f]+)</.exec(t);if(m){{tok=m[1];show()}}else{{document.getElementById('e').textContent='Invalid user name or password'}}}})}};
function show(){{api('<cmd action="read_units"/>').then(function(u){{api('<cmd action="read_devices"/>').then(function(d){{
var name=(/<store_name>([^<]*)</.exec(u)||[])[1]||'',rows='';
d.replace(/<device node="(\d+)" name="([^"]*)" temp="([^"]*)" setpoint="([^"]*)" defrost="(\d)"\/>/g,function(_,n,nm,t,s,f){{
rows+='<tr><td>'+n+'</td><td>'+nm+'</td><td>'+t+' &deg;C</td><td>'+s+' &deg;C</td><td>'+(f=='1'?'Defrost':'Normal')+'</td><td><button data-n="'+n+'">Defrost</button></td></tr>';return ''}});
document.body.innerHTML='<div class="bar"><b>Danfoss</b>ENGINEERING TOMORROW</div><div class="sub">AK-SM800A Series &middot; '+name+'</div><table><tr><th>Node</th><th>Name</th><th>Temp</th><th>Setpoint</th><th>State</th><th></th></tr>'+rows+'</table>'}})}})}}
document.body.onclick=function(ev){{var n=ev.target.getAttribute&&ev.target.getAttribute('data-n');if(n){{api('<cmd action="start_defrost" node="'+n+'"/>').then(show)}}}};
</script></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona() -> Danfoss {
        let cfg = Config::from_env().unwrap();
        Danfoss::new(&cfg, &Identity::generate(&cfg))
    }

    #[test]
    fn the_page_shows_the_cases_after_login_and_offers_a_defrost() {
        // The browser view is driven by the same XML API a script would use, so
        // a click on Defrost is logged exactly like a scripted command.
        let page = build_login_page("SVB501.000.150");
        for needle in ["read_units", "read_devices", "start_defrost", "session_token"] {
            assert!(page.contains(needle), "{needle} missing from the page script");
        }
    }

    #[test]
    fn code_of_the_day_matches_the_documented_algorithm() {
        // Known-answer vectors: our code_of_the_day reproduces the reverse-
        // engineered `check_code_of_day` from the CVE-2025-41450 analysis
        // (Ironhackers; Claroty Team82). The algorithm is
        //   ("MMDDYYMM" read as hex) / ("DD" read as hex), mod 100000, 5 digits.
        // If this drifts, the log's "correct code" tag would start lying.
        let d = persona();
        let code = |y, m, day| d.code_of_the_day(chrono::NaiveDate::from_ymd_opt(y, m, day).unwrap());
        assert_eq!(code(2025, 6, 2), "01923");
        assert_eq!(code(2025, 12, 25), "27681");
        assert_eq!(code(2024, 1, 10), "14688"); // day 10 -> 0x10, the quirky hex-of-decimal step
        assert_ne!(code(2026, 11, 8), code(2026, 11, 9), "a different code each day");
    }

    #[test]
    fn exploit_tags_follow_the_public_advisories() {
        let mut attrs = HashMap::new();
        attrs.insert("filename".to_string(), "../../etc/passwd".to_string());
        assert_eq!(
            Danfoss::exploit_tag("get_file", &attrs),
            Some("CVE-2023-25914 path traversal")
        );
        assert_eq!(
            Danfoss::exploit_tag("load_cert", &HashMap::new()),
            Some("CVE-2023-25915 command injection")
        );
        assert_eq!(Danfoss::exploit_tag("read_units", &HashMap::new()), None);
    }

    #[test]
    fn operator_supplied_firmware_is_escaped_in_the_page() {
        let page = build_login_page("SVB501<script>x</script>");
        assert!(
            !page.contains("<script>x"),
            "FIRMWARE must not reach the page raw"
        );
        assert!(page.contains("SVB501&lt;script&gt;"));
    }

    #[test]
    fn attrs_are_parsed_and_bounded() {
        let d = persona();
        let a = d.parse_attrs(r#"<cmd action="getauth" user="x" password="y"/>"#);
        assert_eq!(a.get("action").map(String::as_str), Some("getauth"));
        assert_eq!(a.len(), 3);
        assert!(d.parse_attrs("not xml at all").is_empty());
        // XML allows either quote; an exploit written with single quotes must
        // still be parsed, or it loses its tag.
        let a = d.parse_attrs(r#"<cmd action='get_file' filename='../../etc/passwd' note="it's"/>"#);
        assert_eq!(
            Danfoss::exploit_tag(&a["action"], &a),
            Some("CVE-2023-25914 path traversal")
        );
        assert_eq!(a.get("note").map(String::as_str), Some("it's"));
    }
}
