//! Runtime configuration, read once from the environment.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persona {
    Danfoss,
    Dixell,
    /// Danfoss AK-SC 355 — the other legacy model named in the CERT-FR alert.
    /// Intentionally shallow: anchored only to publicly documented fingerprints.
    Aksc355,
    /// Carel pCOWeb (thttpd, HTTP Basic). Good fidelity.
    Carel,
    /// Eliwell TelevisGo. Good fidelity.
    Eliwell,
    /// Resource Data Management Data Manager. Medium fidelity.
    Rdm,
}

impl Persona {
    pub fn as_str(self) -> &'static str {
        match self {
            Persona::Danfoss => "danfoss",
            Persona::Dixell => "dixell",
            Persona::Aksc355 => "aksc355",
            Persona::Carel => "carel",
            Persona::Eliwell => "eliwell",
            Persona::Rdm => "rdm",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub persona: Persona,
    pub bind: IpAddr,
    pub http_port: u16,
    pub https_port: u16,
    pub modbus_port: u16,
    pub log_path: PathBuf,
    /// Where the generated certificate is kept across restarts; unset = a
    /// fresh certificate each start.
    pub tls_dir: Option<PathBuf>,
    /// Time zone the decoy pretends to live in (clock, code-of-the-day).
    pub device_tz: chrono_tz::Tz,
    /// Explicit overrides for the generated identity; empty = generate.
    pub store_name: Option<String>,
    pub firmware: Option<String>,
    /// Operator override for the vendor OUI of the generated MAC (`xx:xx:xx`);
    /// unset = the persona's IEEE-registered OUI.
    pub mac_oui: Option<String>,
    /// Override the persona's default Server header. Set it to a value you have
    /// observed on a real unit. Empty by default: for personas whose real header
    /// we cannot cite (AK-SC 355, Eliwell, RDM) a wrong string is a worse tell
    /// than none, so they send none unless this is set.
    pub server_header: Option<String>,
    /// Language of the generated store banner (`it`, `de`, `fr`, `es`, `nl`,
    /// `en`); unset = guessed from `device_tz`.
    pub store_lang: Option<String>,

    // Hard limits. Not environment-tunable on purpose: they are the safety net.
    pub max_body: usize,
    pub max_field: usize,
    pub max_line: usize,
    pub max_conns: u32,
    pub max_per_ip: u32,
    pub max_log_bytes: u64,
    pub log_keep: u32,
    /// Events queued for the log writer thread before new ones are dropped.
    pub log_queue: usize,
    /// Events one source may log per minute, per class (routine / significant).
    pub max_events_per_min: u32,
    pub socket_timeout: Duration,
    pub conn_deadline: Duration,
    pub session_ttl: Duration,
    /// How long shutdown waits for the log writer to drain before exiting anyway.
    pub shutdown_grace: Duration,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env_u16(name: &str, default: u16) -> Result<u16, String> {
    match env(name) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|_| format!("{name}: not a port number: {v:?}")),
    }
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let persona = match env("PERSONA").as_deref().unwrap_or("danfoss") {
            "danfoss" => Persona::Danfoss,
            "dixell" => Persona::Dixell,
            "aksc355" | "aksc" => Persona::Aksc355,
            "carel" | "pcoweb" => Persona::Carel,
            "eliwell" | "televisgo" => Persona::Eliwell,
            "rdm" | "datamanager" => Persona::Rdm,
            other => {
                return Err(format!(
                    "PERSONA: unknown persona {other:?} (danfoss|dixell|aksc355|carel|eliwell|rdm)"
                ))
            }
        };
        let bind: IpAddr = env("BIND")
            .as_deref()
            .unwrap_or("0.0.0.0")
            .parse()
            .map_err(|_| "BIND: not an IP address".to_string())?;
        let device_tz: chrono_tz::Tz = env("DEVICE_TZ")
            .as_deref()
            .unwrap_or("Europe/Rome")
            .parse()
            .map_err(|e| format!("DEVICE_TZ: {e}"))?;
        let mac_oui = env("MAC_OUI").map(|v| v.trim().to_ascii_lowercase());
        if let Some(o) = &mac_oui {
            let pairs: Vec<&str> = o.split(':').collect();
            let ok = pairs.len() == 3
                && pairs
                    .iter()
                    .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
            if !ok {
                return Err(format!("MAC_OUI: expected xx:xx:xx, got {o:?}"));
            }
        }
        let store_lang = env("STORE_LANG").map(|l| l.to_ascii_lowercase());
        if let Some(l) = &store_lang {
            if !["it", "de", "fr", "es", "nl", "en"].contains(&l.as_str()) {
                return Err(format!("STORE_LANG: unknown language {l:?} (it|de|fr|es|nl|en)"));
            }
        }
        Ok(Config {
            persona,
            bind,
            http_port: env_u16("HTTP_PORT", 8080)?,
            https_port: env_u16("HTTPS_PORT", 0)?,
            modbus_port: env_u16("MODBUS_PORT", 0)?,
            log_path: PathBuf::from(env("LOG_PATH").unwrap_or_else(|| "events.jsonl".into())),
            tls_dir: env("TLS_DIR").map(PathBuf::from),
            device_tz,
            store_name: env("STORE_NAME"),
            firmware: env("FIRMWARE"),
            mac_oui,
            server_header: env("SERVER_HEADER"),
            store_lang,
            max_body: 8192,
            max_field: 512,
            max_line: 8192,
            max_conns: 256,
            max_per_ip: 16,
            max_log_bytes: 256 * 1024 * 1024,
            log_keep: 4,
            log_queue: 4096,
            max_events_per_min: 600,
            socket_timeout: Duration::from_secs(15),
            conn_deadline: Duration::from_secs(30),
            session_ttl: Duration::from_secs(3600),
            shutdown_grace: Duration::from_secs(2),
        })
    }
}
