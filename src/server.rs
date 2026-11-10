//! Connection handling: wire the HTTP and Modbus loops to the personas.

use crate::aksc::Aksc355;
use crate::carel::{self, Carel};
use crate::config::{Config, Persona};
use crate::danfoss::Danfoss;
use crate::dixell::{self, Dixell};
use crate::eliwell::Eliwell;
use crate::fields;
use crate::http::{read_request, ReadOutcome, Request, Response};
use crate::identity::Identity;
use crate::logging::Logger;
use crate::modbus::serve_modbus;
use crate::rdm::Rdm;
use crate::state::{Registers, Sessions, Slots};
use crate::util::LoginResult;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

const HTML: &str = "text/html; charset=utf-8";
const JSON: &str = "application/json";

pub struct App {
    pub cfg: Config,
    pub id: Identity,
    pub log: Logger,
    pub slots: Arc<Slots>,
    pub sessions: Arc<Sessions>,
    pub regs: Registers,
    pub unit: Unit,
}

/// The one persona this process impersonates, with its state.
pub enum Unit {
    Danfoss(Danfoss),
    Dixell(Dixell),
    Aksc355(Aksc355),
    Carel(Carel),
    Eliwell(Eliwell),
    Rdm(Rdm),
}

impl App {
    pub fn new(cfg: Config) -> Result<Arc<App>, String> {
        let id = Identity::generate(&cfg);
        let log = Logger::new(&cfg).map_err(|e| format!("log: {e}"))?;
        let unit = match cfg.persona {
            Persona::Danfoss => Unit::Danfoss(Danfoss::new(&cfg, &id)),
            Persona::Dixell => Unit::Dixell(Dixell::new(&cfg, &id)),
            Persona::Aksc355 => Unit::Aksc355(Aksc355::new(&cfg, &id)),
            Persona::Carel => Unit::Carel(Carel::new(&cfg, &id)),
            Persona::Eliwell => Unit::Eliwell(Eliwell::new(&cfg, &id)),
            Persona::Rdm => Unit::Rdm(Rdm::new(&cfg, &id)),
        };
        Ok(Arc::new(App {
            slots: Arc::new(Slots::new(&cfg)),
            sessions: Arc::new(Sessions::new(&cfg)),
            regs: Registers::new(),
            cfg,
            id,
            log,
            unit,
        }))
    }

    fn server_header(&self) -> String {
        if let Some(h) = &self.cfg.server_header {
            return h.clone(); // explicit operator override wins for any persona
        }
        match self.cfg.persona {
            Persona::Danfoss => "nginx".to_string(),
            // pCOWeb's embedded server is documented as thttpd. Exact version is an
            // assumption; override with SERVER_HEADER to match an observed unit.
            // The string itself is SERVER_SOFTWARE in thttpd 2.25b's version.h.
            Persona::Carel => "thttpd/2.25b 29dec2003".to_string(),
            // No reliable public value; send none unless the operator sets one.
            Persona::Dixell | Persona::Aksc355 | Persona::Eliwell | Persona::Rdm => String::new(),
        }
    }

    /// Error body and content type in the style of the persona's web server.
    fn error_page(&self, status: u16, reason: &str, req: &Request) -> (String, &'static str) {
        match self.cfg.persona {
            // nginx's built-in error pages: CRLF lines, no charset on the type.
            Persona::Danfoss => (
                format!(
                    "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n\
                     <center><h1>{status} {reason}</h1></center>\r\n<hr><center>nginx</center>\r\n\
                     </body>\r\n</html>\r\n"
                ),
                "text/html",
            ),
            Persona::Carel => {
                let arg = match status {
                    400 => "",
                    501 => &req.method,
                    _ => &req.path,
                };
                let body = carel::thttpd_error(status, reason, arg, &self.server_header());
                (body, HTML)
            }
            Persona::Dixell | Persona::Aksc355 | Persona::Eliwell | Persona::Rdm => (
                format!(
                    "<html><head><title>{status} {reason}</title></head>\
                     <body><h1>{status} {reason}</h1></body></html>"
                ),
                HTML,
            ),
        }
    }

    /// Status for a method the persona's server does not serve on a static page.
    fn method_refusal(&self) -> (u16, &'static str) {
        match self.cfg.persona {
            Persona::Danfoss => (405, "Not Allowed"),   // nginx's wording
            Persona::Carel => (501, "Not Implemented"), // thttpd refuses with 501, not 405
            Persona::Dixell | Persona::Aksc355 | Persona::Eliwell | Persona::Rdm => {
                (405, "Method Not Allowed")
            }
        }
    }

    /// Status for a request body over `max_body`.
    fn too_large(&self) -> (u16, &'static str) {
        match self.cfg.persona {
            // No 413 is known for thttpd; it answers what it cannot take with 400.
            Persona::Carel => (400, "Bad Request"),
            Persona::Danfoss | Persona::Dixell | Persona::Aksc355 | Persona::Eliwell | Persona::Rdm => {
                (413, "Request Entity Too Large")
            }
        }
    }
}

/// Run one HTTP(S) connection. The whole exchange — reads, login delays and
/// writes — sits under `conn_deadline`, so the socket is dropped after it
/// whatever the client does.
pub async fn serve_http<S>(app: Arc<App>, stream: S, peer: SocketAddr, proto: &'static str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = app.cfg.conn_deadline;
    let _ = tokio::time::timeout(deadline, http_loop(app, stream, peer, proto)).await;
}

async fn http_loop<S>(app: Arc<App>, mut stream: S, peer: SocketAddr, proto: &'static str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Carry-over buffer: pipelined bytes survive between requests.
    let mut buf = Vec::new();
    loop {
        let read = read_request(&mut stream, &mut buf, app.cfg.max_body);
        let req = match tokio::time::timeout(app.cfg.socket_timeout, read).await {
            Ok(Ok(ReadOutcome::Ok(r))) => r,
            // Refused, never dispatched; but answered as the real server would,
            // since closing in silence is a tell shared by every persona.
            Ok(Ok(ReadOutcome::Bad(line))) => {
                log_refused(&app, proto, peer, line);
                send_error(&app, &mut stream, &Request::default(), 400, "Bad Request").await;
                return linger(&mut stream).await;
            }
            Ok(Ok(ReadOutcome::TooLarge(line))) => {
                log_refused(&app, proto, peer, line);
                let (status, reason) = app.too_large();
                send_error(&app, &mut stream, &Request::default(), status, reason).await;
                return linger(&mut stream).await;
            }
            Ok(Ok(ReadOutcome::Truncated(line))) => return log_refused(&app, proto, peer, line),
            _ => return, // Eof, idle timeout or IO error
        };
        if !dispatch_http(&app, &mut stream, peer, proto, &req).await {
            return;
        }
    }
}

/// Log a refused request. It never reaches `dispatch_http`, so tag the exploit
/// here from the request line: an upload over the body cap is still an attempt.
fn log_refused(app: &App, proto: &str, peer: SocketAddr, line: String) {
    let path = line.split_whitespace().nth(1).unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let exploit = (app.cfg.persona == Persona::Dixell)
        .then(|| dixell::exploit_path(path))
        .flatten();
    app.log.log(
        proto,
        peer,
        "bad_request",
        fields! { "raw" => line, "exploit" => exploit },
    );
}

/// Lingering close after refusing a request. Closing a socket that still holds
/// unread request bytes makes the kernel send RST, which can destroy the error
/// reply before the client reads it. So half-close, then discard what is still
/// arriving: briefly and bounded, and still inside `conn_deadline`.
async fn linger<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const LINGER: Duration = Duration::from_millis(250); // short: the slot is held meanwhile
    const LINGER_BYTES: usize = 64 * 1024;
    let _ = stream.shutdown().await;
    let drain = async {
        let mut sink = [0u8; 4096];
        let mut left = LINGER_BYTES;
        while left > 0 {
            match stream.read(&mut sink).await {
                Ok(n) if n > 0 => left = left.saturating_sub(n),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
}

/// Returns true if the connection may stay open for another request.
async fn dispatch_http<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    let path_only = req.path.split(['?', '#']).next().unwrap_or(&req.path).to_string();

    let dixell_exploit = if app.cfg.persona == Persona::Dixell {
        dixell::exploit_path(&path_only)
    } else {
        None
    };

    app.log.log(
        proto,
        peer,
        "request",
        fields! {
            "method" => req.method,
            "path" => req.path,
            "host" => req.headers.get("host").cloned().unwrap_or_default(),
            "user_agent" => req.headers.get("user-agent").cloned().unwrap_or_default(),
            "authorization" => req.headers.get("authorization").cloned().unwrap_or_default(),
            "body" => req.text(),
            "exploit" => dixell_exploit,
        },
    );

    // nginx answers 400 to a method that is not upper-case letters, `_` or `-`
    // (`get /`), before any routing. Only nginx: thttpd matches case-blind, and
    // the other personas' servers are unknown.
    let nginx_method = |b: u8| b.is_ascii_uppercase() || b == b'_' || b == b'-';
    if app.cfg.persona == Persona::Danfoss && !req.method.bytes().all(nginx_method) {
        return send_error(app, stream, req, 400, "Bad Request").await;
    }

    match &app.unit {
        Unit::Danfoss(d) => dispatch_danfoss(app, stream, peer, proto, req, &path_only, d).await,
        Unit::Dixell(d) => dispatch_dixell(app, stream, peer, proto, req, &path_only, d).await,
        Unit::Aksc355(a) => dispatch_aksc(app, stream, peer, proto, req, &path_only, a).await,
        Unit::Carel(c) => dispatch_carel(app, stream, peer, proto, req, &path_only, c).await,
        Unit::Eliwell(e) => dispatch_eliwell(app, stream, peer, proto, req, &path_only, e).await,
        Unit::Rdm(d) => dispatch_rdm(app, stream, peer, proto, req, &path_only, d).await,
    }
}

/// Write one response and close the connection: the common case for every persona.
async fn send<S>(
    app: &Arc<App>,
    stream: &mut S,
    req: &Request,
    status: u16,
    reason: &'static str,
    body: Vec<u8>,
    ctype: &str,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    let _ = reply(app, status, reason, body, ctype, false, req)
        .write(stream)
        .await;
    false
}

async fn not_found<S>(app: &Arc<App>, stream: &mut S, req: &Request) -> bool
where
    S: AsyncWrite + Unpin,
{
    send_error(app, stream, req, 404, "Not Found").await
}

/// Answer with the persona's error page for `status` and close.
async fn send_error<S>(
    app: &Arc<App>,
    stream: &mut S,
    req: &Request,
    status: u16,
    reason: &'static str,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    let (body, ctype) = app.error_page(status, reason, req);
    send(app, stream, req, status, reason, body.into_bytes(), ctype).await
}

/// Serve a persona's landing page the way a web server serves a static file:
/// GET and HEAD only. `static_asset` adds nginx's static-file headers and
/// keep-alive. Returns true if the connection may stay open.
async fn page<S>(app: &Arc<App>, stream: &mut S, req: &Request, body: &str, static_asset: bool) -> bool
where
    S: AsyncWrite + Unpin,
{
    // thttpd matches method names case-blind; everything else here is exact.
    let method = match app.cfg.persona {
        Persona::Carel => req.method.to_ascii_uppercase(),
        _ => req.method.clone(),
    };
    if method != "GET" && method != "HEAD" {
        let (status, reason) = app.method_refusal();
        return send_error(app, stream, req, status, reason).await;
    }
    let r = reply(app, 200, "OK", body.as_bytes().to_vec(), HTML, static_asset, req);
    let keep = !r.close;
    let _ = r.write(stream).await;
    keep
}

/// Answer a login after the human-like delay the handler chose.
async fn send_login<S>(app: &Arc<App>, stream: &mut S, req: &Request, res: LoginResult) -> bool
where
    S: AsyncWrite + Unpin,
{
    tokio::time::sleep(res.delay).await;
    send(app, stream, req, 200, "OK", res.body.into_bytes(), JSON).await
}

async fn dispatch_carel<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    c: &Carel,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    // /config/ is HTTP Basic protected on real units.
    if path.starts_with("/config/") {
        let auth = req.headers.get("authorization").map(|s| s.as_str());
        return match c.config_request(&app.log, peer, proto, path, auth) {
            Some((status, body)) => {
                let reason = if status == 200 { "OK" } else { "Forbidden" };
                send(app, stream, req, status, reason, body.into_bytes(), HTML).await
            }
            None => {
                // 401 challenge with the realm the unit presents; thttpd writes
                // it after its fixed headers, so it comes last.
                let (body, ctype) = app.error_page(401, "Unauthorized", req);
                let mut r = reply(app, 401, "Unauthorized", body.into_bytes(), ctype, false, req);
                let challenge = format!("Basic realm=\"{}\"", c.basic_realm());
                r.headers.push(("WWW-Authenticate".into(), challenge));
                let _ = r.write(stream).await;
                false
            }
        };
    }
    if path == "/" || path == "/index.html" || path == "/http/index.html" {
        return page(app, stream, req, &c.demo_page, false).await;
    }
    not_found(app, stream, req).await
}

async fn dispatch_eliwell<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    e: &Eliwell,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    if (path == "/login" || path == "/j_security_check") && req.method == "POST" {
        let res = e.login(&app.log, &app.sessions, peer, proto, &req.text());
        return send_login(app, stream, req, res).await;
    }
    if path == "/welcome" || path == "/version" {
        return send(app, stream, req, 200, "OK", e.welcome().into_bytes(), JSON).await;
    }
    if path == "/" || path == "/index.html" {
        return page(app, stream, req, &e.login_page, false).await;
    }
    not_found(app, stream, req).await
}

async fn dispatch_rdm<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    d: &Rdm,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    if (path == "/cgi-bin/login.cgi" || path == "/login") && req.method == "POST" {
        let res = d.login(&app.log, &app.sessions, peer, proto, &req.text());
        return send_login(app, stream, req, res).await;
    }
    if path == "/cgi-bin/status.cgi" || path == "/status" {
        return send(
            app,
            stream,
            req,
            200,
            "OK",
            d.status(&app.regs).into_bytes(),
            JSON,
        )
        .await;
    }
    if path == "/" || path == "/index.html" {
        return page(app, stream, req, &d.login_page, false).await;
    }
    not_found(app, stream, req).await
}

async fn dispatch_aksc<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    a: &Aksc355,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    if (path == "/cgi-bin/login.cgi" || path == "/login") && req.method == "POST" {
        let res = a.login(&app.log, &app.sessions, peer, proto, &req.text());
        return send_login(app, stream, req, res).await;
    }
    if (path == "/cgi-bin/reset.cgi" || path == "/reset") && req.method == "POST" {
        let body = a.reset(&app.log, peer, proto).into_bytes();
        return send(app, stream, req, 200, "OK", body, JSON).await;
    }
    if path == "/" || path == "/index.html" {
        return page(app, stream, req, &a.login_page, false).await;
    }
    not_found(app, stream, req).await
}

async fn dispatch_danfoss<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    d: &Danfoss,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    if path == "/html/xml.cgi" || path == "/xml.cgi" {
        return match req.method.as_str() {
            "POST" => {
                let out = d.handle_xml(&app.log, &app.sessions, &app.regs, peer, proto, req);
                if let Some(delay) = out.delay {
                    tokio::time::sleep(delay).await;
                }
                send(
                    app,
                    stream,
                    req,
                    200,
                    "OK",
                    out.body.into_bytes(),
                    "text/xml; charset=utf-8",
                )
                .await
            }
            "OPTIONS" => send(app, stream, req, 204, "No Content", Vec::new(), "text/plain").await,
            _ => send_error(app, stream, req, 405, "Not Allowed").await,
        };
    }
    if path == "/" || path == "/index.html" {
        // nginx serves the login page as a static file and keeps the connection
        // open unless the client asked to close it.
        return page(app, stream, req, &d.login_page, true).await;
    }
    not_found(app, stream, req).await
}

async fn dispatch_dixell<S>(
    app: &Arc<App>,
    stream: &mut S,
    peer: SocketAddr,
    proto: &'static str,
    req: &Request,
    path: &str,
    d: &Dixell,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    // Static assets: empty 200 so the page does not trail 404s.
    let is_script = path
        .strip_prefix("/js/")
        .is_some_and(|n| dixell::SCRIPTS.contains(&n));
    let is_style = path
        .strip_prefix("/css/")
        .is_some_and(|n| dixell::STYLES.contains(&n));
    if is_script || is_style {
        let ctype = if is_style {
            "text/css"
        } else {
            "application/javascript"
        };
        return send(app, stream, req, 200, "OK", Vec::new(), ctype).await;
    }

    if (path == "/cgi-bin/login.lua" || path == "/login") && req.method == "POST" {
        let res = d.login(&app.log, &app.sessions, peer, proto, &req.text());
        return send_login(app, stream, req, res).await;
    }
    if path == "/cgi-bin/datachart.cgi" && req.method == "POST" {
        return match d.datachart(&app.log, &app.sessions, &app.regs, peer, proto, &req.text()) {
            Some(json) => send(app, stream, req, 200, "OK", json.into_bytes(), JSON).await,
            // Expired session -> login page, as on real units.
            None => {
                send(
                    app,
                    stream,
                    req,
                    200,
                    "OK",
                    d.login_page.clone().into_bytes(),
                    HTML,
                )
                .await
            }
        };
    }

    // CVE-2021-45420: upload CGIs "write" a file; GET /logo/<name> retrieves it.
    let is_upload_cgi = path == "/cgi-bin/logo_extra_upload.cgi"
        || path == "/cgi-bin/cal_save.cgi"
        || path == "/cgi-bin/lo_utils.cgi";
    if is_upload_cgi && req.method == "POST" {
        let body = d.upload(&app.log, peer, proto, path, &req.body).into_bytes();
        return send(app, stream, req, 200, "OK", body, "text/plain").await;
    }
    if path == "/cgi-bin/cal_dir.cgi" || path == "/logo/" {
        return send(app, stream, req, 200, "OK", d.dir_listing().into_bytes(), HTML).await;
    }
    if let Some(data) = path.strip_prefix("/logo/").and_then(|name| d.fetch_upload(name)) {
        return send(app, stream, req, 200, "OK", data, "application/octet-stream").await;
    }

    if path == "/" || path == "/index.html" {
        return page(app, stream, req, &d.login_page, false).await;
    }
    not_found(app, stream, req).await
}

/// Build a response with persona-correct headers and order.
fn reply(
    app: &Arc<App>,
    status: u16,
    reason: &'static str,
    body: Vec<u8>,
    content_type: &str,
    static_asset: bool,
    req: &Request,
) -> Response {
    let carel = app.cfg.persona == Persona::Carel;
    // thttpd matches method names case-blind and answers in the request's version.
    let head_only = req.method == "HEAD" || (carel && req.method.eq_ignore_ascii_case("HEAD"));
    let version = if carel && req.version == "HTTP/1.0" {
        "HTTP/1.0"
    } else {
        "HTTP/1.1"
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut close = true;

    match app.cfg.persona {
        Persona::Carel => {
            // thttpd 2.25b send_mime(): Server, Content-Type (its charset is
            // iso-8859-1), Date, Last-Modified, Accept-Ranges, Connection.
            // Then Content-Length, or on an error page Cache-Control instead:
            // thttpd sends its error pages without a length.
            let ok = (200..400).contains(&status);
            let ctype = if content_type == HTML {
                "text/html; charset=iso-8859-1"
            } else {
                content_type
            };
            let now = httpdate_now();
            let modified = if ok {
                httpdate(app.id.firmware_mtime)
            } else {
                now.clone()
            };
            headers.push(("Content-Type".into(), ctype.into()));
            headers.push(("Date".into(), now));
            headers.push(("Last-Modified".into(), modified));
            headers.push(("Accept-Ranges".into(), "bytes".into()));
            headers.push(("Connection".into(), "close".into()));
            if ok {
                headers.push(("Content-Length".into(), body.len().to_string()));
            } else {
                headers.push(("Cache-Control".into(), "no-cache,no-store".into()));
            }
        }
        Persona::Dixell => {
            // Header set, order (Date last) and the bare `text/html` type are
            // those of a real XWEB EVO's Shodan banner (see FINGERPRINTS.md).
            // It sends no Server header; ours appears only if the operator sets
            // SERVER_HEADER (then it is written first, like any persona's).
            let ctype = if content_type == HTML {
                "text/html"
            } else {
                content_type
            };
            headers.push(("Content-Type".into(), ctype.into()));
            for (k, v) in DIXELL_HEADERS {
                headers.push(((*k).into(), (*v).into()));
            }
            headers.push(("Content-Length".into(), body.len().to_string()));
            headers.push(("Date".into(), httpdate_now()));
        }
        Persona::Danfoss | Persona::Aksc355 | Persona::Eliwell | Persona::Rdm => {
            // Server first (written by the writer; empty for personas without a
            // known header unless SERVER_HEADER is set), then Date, then the rest.
            headers.push(("Date".into(), httpdate_now()));
            headers.push(("Content-Type".into(), content_type.into()));
            headers.push(("Content-Length".into(), body.len().to_string()));
            if static_asset {
                // nginx keeps a static-file connection alive unless the client
                // asked to close, and echoes whichever applies.
                let keep = req.wants_keep_alive();
                let mtime = app.id.firmware_mtime;
                headers.push(("Last-Modified".into(), httpdate(mtime)));
                headers.push((
                    "Connection".into(),
                    if keep { "keep-alive" } else { "close" }.into(),
                ));
                headers.push(("ETag".into(), format!("\"{:x}-{:x}\"", mtime, body.len())));
                for (k, v) in DANFOSS_STATIC_HEADERS {
                    headers.push(((*k).into(), (*v).into()));
                }
                close = !keep;
            } else {
                headers.push(("Connection".into(), "close".into()));
            }
        }
    }

    Response {
        status,
        reason,
        headers,
        body,
        server: app.server_header(),
        close,
        head_only,
        version,
    }
}

const DANFOSS_STATIC_HEADERS: &[(&str, &str)] = &[
    ("Access-Control-Allow-Origin", "*"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    (
        "Access-Control-Allow-Headers",
        "aksm-auth,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type",
    ),
    ("Cache-Control", "no-store, no-cache"),
    ("Accept-Ranges", "bytes"),
];

const DIXELL_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store, max-age=0"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Robots-Tag", "noindex, nofollow"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; \
      font-src 'self'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-src 'self'; \
      object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri 'none'",
    ),
    (
        "Feature-Policy",
        "camera 'none'; microphone 'none'; geolocation 'none'",
    ),
    (
        "Permissions-Policy",
        "camera 'none'; microphone 'none'; geolocation 'none'",
    ),
    ("Referrer-Policy", "no-referrer"),
    ("Vary", "User-Agent"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "1; mode=block"),
    ("X-UA-Compatible", "IE=edge"),
];

fn httpdate_now() -> String {
    httpdate(chrono::Utc::now().timestamp() as u64)
}

fn httpdate(secs: u64) -> String {
    use chrono::{TimeZone, Utc};
    let dt = Utc
        .timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Accept loop shared by all TCP services, applying the per-source slot cap.
pub async fn accept_loop(app: Arc<App>, listener: TcpListener, kind: Service) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let guard = match app.slots.take(peer.ip()) {
            Some(g) => g,
            None => {
                if app.slots.should_log_refusal(peer.ip()) {
                    app.log.log("tcp", peer, "conn_refused", fields! {});
                }
                drop(stream);
                continue;
            }
        };
        let app2 = app.clone();
        let kind = kind.clone();
        tokio::spawn(async move {
            let _guard = guard; // freed on task end
            let _ = stream.set_nodelay(true);
            match kind {
                Service::Http => serve_http(app2, stream, peer, "http").await,
                Service::Modbus => serve_modbus(app2, stream, peer).await,
                Service::Https(cfg) => {
                    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                    match tokio::time::timeout(app2.cfg.socket_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => serve_http(app2, tls, peer, "https").await,
                        Ok(Err(e)) => {
                            app2.log
                                .log("https", peer, "tls_error", fields! { "error" => e.to_string() });
                        }
                        Err(_) => {
                            app2.log.log(
                                "https",
                                peer,
                                "tls_error",
                                fields! { "error" => "handshake timeout" },
                            );
                        }
                    }
                }
            }
        });
    }
}

#[derive(Clone)]
pub enum Service {
    Http,
    Https(Arc<rustls::ServerConfig>),
    Modbus,
}
