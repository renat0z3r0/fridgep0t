//! Event logging: one JSON object per line, on stdout and appended to a file.
//!
//! Every field a logged event carries from the attacker is clipped, and the
//! whole line is capped, so a flood of binary junk cannot blow up the log or a
//! downstream parser. The file rotates once it grows past the cap.
//!
//! Writing happens on one dedicated thread fed by a bounded queue, so a slow
//! disk or stdout consumer stalls the writer, never the connection tasks. When
//! the queue is full the newest event is dropped and counted; the count is
//! reported as a `log_dropped` system event once writing catches up.

use crate::config::Config;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Logger {
    persona: &'static str,
    max_field: usize,
    max_line: usize,
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    /// Signalled once by the writer when it has drained the queue and stopped.
    done: Mutex<Receiver<()>>,
    shutdown_grace: Duration,
    limiter: Limiter,
}

enum Msg {
    Line(String),
    Close,
}

#[derive(Serialize)]
struct Head<'a> {
    ts: String,
    persona: &'a str,
    proto: &'a str,
    src_ip: String,
    src_port: u16,
    event: &'a str,
}

impl Logger {
    pub fn new(cfg: &Config) -> std::io::Result<Logger> {
        // Opened here, not on the thread, so an unwritable path fails startup.
        let file = OpenOptions::new().create(true).append(true).open(&cfg.log_path)?;
        let persona = persona_static(cfg.persona.as_str());
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = sync_channel(cfg.log_queue);
        let (done_tx, done_rx) = channel();
        let writer = Writer {
            done: done_tx,
            persona,
            path: cfg.log_path.clone(),
            file,
            max_log_bytes: cfg.max_log_bytes,
            log_keep: cfg.log_keep,
            dropped: dropped.clone(),
        };
        // Detached: shutdown waits on `done` with a deadline, never on a join.
        std::thread::Builder::new()
            .name("fridgep0t-log".into())
            .spawn(move || writer.run(rx))?;
        Ok(Logger {
            persona,
            max_field: cfg.max_field,
            max_line: cfg.max_line,
            tx,
            dropped,
            done: Mutex::new(done_rx),
            shutdown_grace: cfg.shutdown_grace,
            limiter: Limiter {
                per_min: cfg.max_events_per_min,
                windows: Mutex::new(HashMap::new()),
            },
        })
    }

    /// Record one event. `details` is a flat set of extra fields. A source over
    /// its per-minute budget gets one `log_suppressed` marker, then silence
    /// until the minute is up.
    pub fn log(&self, proto: &str, src: SocketAddr, event: &str, details: Map<String, Value>) {
        let significant = SIGNIFICANT.contains(&event);
        match self.limiter.admit(src.ip(), significant, Instant::now()) {
            Admit::Write => self.emit(proto, src, event, details),
            Admit::Mark => {
                let class = if significant { "significant" } else { "routine" };
                let details = crate::fields! { "class" => class, "per_minute" => self.limiter.per_min };
                self.emit(proto, src, "log_suppressed", details);
            }
            Admit::Drop => {}
        }
    }

    fn emit(&self, proto: &str, src: SocketAddr, event: &str, details: Map<String, Value>) {
        let head = Head {
            ts: now(),
            persona: self.persona,
            proto,
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            event,
        };
        let mut obj = match serde_json::to_value(&head) {
            Ok(Value::Object(m)) => m,
            _ => return,
        };
        for (k, mut val) in details {
            clip_value(&mut val, self.max_field);
            obj.insert(k, val);
        }

        let mut line = serde_json::to_string(&obj).unwrap_or_default();
        if line.len() > self.max_line {
            // Escaping can inflate binary junk; clip hard and flag it.
            for val in obj.values_mut() {
                clip_value(val, 64);
            }
            obj.insert("truncated".into(), Value::Bool(true));
            line = serde_json::to_string(&obj).unwrap_or_default();
        }

        // Queue full (or writer gone): drop this event and count it rather than
        // block the connection task behind the disk.
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Events dropped on a full queue and not yet reported in the log.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Give the writer `shutdown_grace` to drain the queue, then return. A stdout
    /// consumer that has stopped reading must not keep the process alive after
    /// SIGTERM; whatever is still queued then is lost, like any crash would lose it.
    pub fn close(&self) {
        let _ = self.tx.try_send(Msg::Close); // a full queue means the writer is stuck anyway
        if let Ok(done) = self.done.lock() {
            let _ = done.recv_timeout(self.shutdown_grace);
        }
    }
}

/// Events that record what a source did, not merely that it knocked. They have
/// a budget of their own, so a flood of plain requests cannot use up the room
/// for the login or the defrost command that follows it.
const SIGNIFICANT: &[&str] = &["login_attempt", "xml_cmd", "control", "write"];

/// Per-source event budget. The log is kept by size, so without it one source
/// could write until rotation had pushed everyone else's events off the disk.
struct Limiter {
    per_min: u32,
    windows: Mutex<HashMap<(IpAddr, bool), (Instant, u32)>>,
}

#[derive(Debug, PartialEq)]
enum Admit {
    Write,
    /// First event over the budget: write a `log_suppressed` marker instead.
    Mark,
    Drop,
}

impl Limiter {
    /// Count one event from `ip` at `now` against its class's budget.
    fn admit(&self, ip: IpAddr, significant: bool, now: Instant) -> Admit {
        let Ok(mut windows) = self.windows.lock() else {
            return Admit::Write;
        };
        // Deliberately simple: fixed one-minute windows and a wholesale clear at 10k
        // sources; a sliding window or LRU if scanners learn to straddle them.
        if windows.len() > 10_000 {
            windows.clear();
        }
        let (start, count) = windows.entry((ip, significant)).or_insert((now, 0));
        if now.duration_since(*start) >= Duration::from_secs(60) {
            (*start, *count) = (now, 0);
        }
        *count = count.saturating_add(1);
        match (*count).cmp(&(self.per_min + 1)) {
            std::cmp::Ordering::Less => Admit::Write,
            std::cmp::Ordering::Equal => Admit::Mark,
            std::cmp::Ordering::Greater => Admit::Drop,
        }
    }
}

/// The single owner of the log file and of stdout writes.
struct Writer {
    done: Sender<()>,
    persona: &'static str,
    path: PathBuf,
    file: File,
    max_log_bytes: u64,
    log_keep: u32,
    dropped: Arc<AtomicU64>,
}

impl Writer {
    fn run(mut self, rx: Receiver<Msg>) {
        // `Close`, or every sender gone, ends the loop.
        while let Ok(Msg::Line(line)) = rx.recv() {
            self.write(&line);
            let n = self.dropped.swap(0, Ordering::Relaxed);
            if n > 0 {
                let report = self.dropped_line(n);
                self.write(&report);
            }
        }
        let _ = self.done.send(());
    }

    fn write(&mut self, line: &str) {
        {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
        let _ = writeln!(self.file, "{line}");
        if self.file.stream_position().unwrap_or(0) > self.max_log_bytes {
            self.rotate();
        }
    }

    fn rotate(&mut self) {
        let p = &self.path;
        for i in (1..self.log_keep).rev() {
            let _ = std::fs::rename(rotated(p, i), rotated(p, i + 1));
        }
        let _ = std::fs::rename(p, rotated(p, 1));
        if let Ok(new) = OpenOptions::new().create(true).append(true).open(p) {
            self.file = new;
        }
    }

    fn dropped_line(&self, count: u64) -> String {
        let head = Head {
            ts: now(),
            persona: self.persona,
            proto: "system",
            src_ip: "0.0.0.0".into(),
            src_port: 0,
            event: "log_dropped",
        };
        let mut obj = match serde_json::to_value(&head) {
            Ok(Value::Object(m)) => m,
            _ => return String::new(),
        };
        obj.insert("count".into(), Value::from(count));
        serde_json::to_string(&Value::Object(obj)).unwrap_or_default()
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn clip_value(v: &mut Value, limit: usize) {
    match v {
        Value::String(s) => {
            if s.chars().count() > limit {
                *s = s.chars().take(limit).collect();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|i| clip_value(i, limit)),
        Value::Object(map) => map.values_mut().for_each(|i| clip_value(i, limit)),
        _ => {}
    }
}

/// `events.jsonl` rotates to `events.jsonl.1`, `.2`, ... (not `events.1`).
fn rotated(path: &Path, i: u32) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.{i}"))
}

fn persona_static(s: &str) -> &'static str {
    match s {
        "dixell" => "dixell",
        "aksc355" => "aksc355",
        "carel" => "carel",
        "eliwell" => "eliwell",
        "rdm" => "rdm",
        _ => "danfoss",
    }
}

/// Build a details map ergonomically: `fields!{ "a" => 1, "b" => "x" }`.
#[macro_export]
macro_rules! fields {
    ( $( $k:expr => $v:expr ),* $(,)? ) => {{
        #[allow(unused_mut)]
        let mut m = serde_json::Map::new();
        $( m.insert($k.to_string(), serde_json::json!($v)); )*
        m
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_keeps_the_full_file_name() {
        assert_eq!(
            rotated(Path::new("/var/log/events.jsonl"), 1),
            PathBuf::from("/var/log/events.jsonl.1")
        );
        assert_eq!(
            rotated(Path::new("events.jsonl"), 3),
            PathBuf::from("events.jsonl.3")
        );
    }

    #[test]
    fn one_source_cannot_flood_the_log_or_bury_its_own_commands() {
        let l = Limiter {
            per_min: 3,
            windows: Mutex::new(HashMap::new()),
        };
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let t0 = Instant::now();
        let got: Vec<Admit> = (0..5).map(|_| l.admit(a, false, t0)).collect();
        assert_eq!(
            got,
            [Admit::Write, Admit::Write, Admit::Write, Admit::Mark, Admit::Drop],
            "budget, one marker, then silence"
        );
        assert_eq!(
            l.admit(a, true, t0),
            Admit::Write,
            "its significant events have their own budget"
        );
        assert_eq!(
            l.admit(b, false, t0),
            Admit::Write,
            "other sources are unaffected"
        );
        assert_eq!(l.admit(a, false, t0 + Duration::from_secs(59)), Admit::Drop);
        assert_eq!(
            l.admit(a, false, t0 + Duration::from_secs(60)),
            Admit::Write,
            "a new minute, a new budget"
        );
    }

    #[test]
    fn clip_recurses_into_nested_values() {
        let mut v = serde_json::json!({ "a": "x".repeat(100), "b": ["y".repeat(100)] });
        clip_value(&mut v, 10);
        assert_eq!(v["a"].as_str().map(str::len), Some(10));
        assert_eq!(v["b"][0].as_str().map(str::len), Some(10));
    }

    #[test]
    fn events_reach_the_file_in_order_and_close_flushes() {
        let dir = std::env::temp_dir().join(format!("fridgep0t-logtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut cfg = Config::from_env().unwrap();
        cfg.log_path = path.clone();
        let log = Logger::new(&cfg).unwrap();
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        for i in 0..3 {
            log.log(
                "http",
                src,
                "request",
                crate::fields! { "n" => i, "junk" => "z".repeat(5000) },
            );
        }
        log.close();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(
            lines.len(),
            3,
            "every queued event is written before close returns"
        );
        assert_eq!(lines[2]["n"], 2);
        assert_eq!(lines[0]["src_ip"], "10.0.0.1");
        assert_eq!(
            lines[0]["junk"].as_str().map(str::len),
            Some(cfg.max_field),
            "fields are clipped"
        );
        assert_eq!(log.dropped(), 0);
        log.close(); // a second close returns at once: the writer is gone
        let _ = std::fs::remove_dir_all(&dir);
    }
}
