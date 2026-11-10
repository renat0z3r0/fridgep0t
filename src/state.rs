//! Shared, in-memory decoy state.

use crate::config::Config;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const CASE_NAMES: [&str; 8] = [
    "Frozen 1",
    "Frozen 2",
    "Ice cream",
    "Frozen 4",
    "Dairy",
    "Meat",
    "Deli",
    "Produce",
];

/// Connection accounting, so one source cannot crowd out the others.
pub struct Slots {
    inner: Mutex<SlotsInner>,
    max_conns: u32,
    max_per_ip: u32,
}

struct SlotsInner {
    active: HashMap<std::net::IpAddr, u32>,
    total: u32,
    refused: HashMap<std::net::IpAddr, Instant>,
}

impl Slots {
    pub fn new(cfg: &Config) -> Slots {
        Slots {
            inner: Mutex::new(SlotsInner {
                active: HashMap::new(),
                total: 0,
                refused: HashMap::new(),
            }),
            max_conns: cfg.max_conns,
            max_per_ip: cfg.max_per_ip,
        }
    }

    /// Reserve a slot. Returns a guard that frees it on drop, or None if full.
    pub fn take(self: &std::sync::Arc<Self>, ip: std::net::IpAddr) -> Option<SlotGuard> {
        let mut g = self.inner.lock().unwrap();
        let per_ip = g.active.get(&ip).copied().unwrap_or(0);
        if g.total >= self.max_conns || per_ip >= self.max_per_ip {
            return None;
        }
        g.total += 1;
        *g.active.entry(ip).or_insert(0) += 1;
        Some(SlotGuard {
            slots: self.clone(),
            ip,
        })
    }

    /// True at most once a minute per source, so refusals are logged sparsely.
    pub fn should_log_refusal(&self, ip: std::net::IpAddr) -> bool {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        if let Some(last) = g.refused.get(&ip) {
            if now.duration_since(*last) < Duration::from_secs(60) {
                return false;
            }
        }
        if g.refused.len() > 10_000 {
            g.refused.clear();
        }
        g.refused.insert(ip, now);
        true
    }

    fn give(&self, ip: std::net::IpAddr) {
        let mut g = self.inner.lock().unwrap();
        g.total = g.total.saturating_sub(1);
        if let Some(c) = g.active.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                g.active.remove(&ip);
            }
        }
    }
}

pub struct SlotGuard {
    slots: std::sync::Arc<Slots>,
    ip: std::net::IpAddr,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.slots.give(self.ip);
    }
}

const MAX_SESSIONS: usize = 1000;

/// Session tokens granted to "successful" logins.
pub struct Sessions {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl Sessions {
    pub fn new(cfg: &Config) -> Sessions {
        Sessions {
            inner: Mutex::new(HashMap::new()),
            ttl: cfg.session_ttl,
        }
    }

    pub fn new_token(&self) -> String {
        let token: String = {
            let mut rng = rand::thread_rng();
            (0..64)
                .map(|_| std::char::from_digit(rng.gen_range(0..16), 16).unwrap_or('0'))
                .collect()
        };
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, &mut exp| exp > now);
        // At the cap the oldest session goes, not all of them: a burst of
        // logins must not log out whoever is already poking around.
        // Deliberately simple: linear scan for the oldest, fine at 1000 entries.
        while g.len() >= MAX_SESSIONS {
            let Some(oldest) = g.iter().min_by_key(|(_, &exp)| exp).map(|(k, _)| k.clone()) else {
                break;
            };
            g.remove(&oldest);
        }
        g.insert(token.clone(), now + self.ttl);
        token
    }

    pub fn valid(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let g = self.inner.lock().unwrap();
        g.get(token).map(|&exp| exp > Instant::now()).unwrap_or(false)
    }
}

/// Fake Modbus holding registers and the defrost simulation.
///   0..7     case temperatures (tenths of deg C, signed, stored as i32)
///   100..107 case setpoints
///   200..207 defrost command (1 = defrosting)
///
/// Each case moves through three phases: normal; defrost, during which the air
/// temperature climbs about 1.5 C/min and caps at +25 C; recovery, during which
/// it pulls back down to base over RECOVERY_SECONDS. A real case does not snap
/// back the moment the heaters stop, so a poller watching the registers must
/// not see that here either. Every method has an `_at` twin taking the clock,
/// so tests can walk through the phases without waiting.
pub struct Registers {
    inner: Mutex<RegInner>,
}

struct RegInner {
    regs: HashMap<u16, i32>,
    phase: HashMap<u16, Phase>,
}

#[derive(Clone, Copy)]
enum Phase {
    Normal,
    Defrost { since: Instant },
    Recovery { since: Instant, peak: i32 },
}

const DEFROST_SECONDS: f64 = 20.0 * 60.0;
const RECOVERY_SECONDS: f64 = 45.0 * 60.0;
const RISE_CAP_TENTHS: f64 = 250.0;

/// Temperature rise after `elapsed` seconds of defrost, in tenths of a degree.
fn rise(elapsed: f64) -> i32 {
    (elapsed / 4.0).min(RISE_CAP_TENTHS) as i32 // ~1.5 C/min, cap 25 C
}

/// Pull-down from `peak` back to 0 over RECOVERY_SECONDS.
fn recovery_offset(peak: i32, t: f64) -> i32 {
    // Deliberately simple: linear pull-down; swap in a measured curve if a real trace says so.
    (peak as f64 * (1.0 - t / RECOVERY_SECONDS)).max(0.0) as i32
}

impl RegInner {
    /// Advance one case's phase to `now`: an expired defrost becomes recovery
    /// and clears its command register; a finished recovery becomes normal.
    fn settle(&mut self, case: u16, now: Instant) {
        let mut phase = self.phase.get(&case).copied().unwrap_or(Phase::Normal);
        if let Phase::Defrost { since } = phase {
            if now.duration_since(since).as_secs_f64() > DEFROST_SECONDS {
                self.regs.insert(200 + case, 0);
                let ended = since + Duration::from_secs_f64(DEFROST_SECONDS);
                phase = Phase::Recovery {
                    since: ended,
                    peak: rise(DEFROST_SECONDS),
                };
            }
        }
        if let Phase::Recovery { since, .. } = phase {
            if now.duration_since(since).as_secs_f64() >= RECOVERY_SECONDS {
                phase = Phase::Normal;
            }
        }
        self.phase.insert(case, phase);
    }

    /// Settle every case first, whatever register is about to be touched: a
    /// command register read alone must show an expired defrost as 0, and a
    /// fresh start command must not land on a stale phase.
    fn settle_all(&mut self, now: Instant) {
        for case in 0..CASE_NAMES.len() as u16 {
            self.settle(case, now);
        }
    }

    /// Temperature offset of a settled case.
    fn offset(&self, case: u16, now: Instant) -> i32 {
        match self.phase.get(&case).copied().unwrap_or(Phase::Normal) {
            Phase::Normal => 0,
            Phase::Defrost { since } => rise(now.duration_since(since).as_secs_f64()),
            Phase::Recovery { since, peak } => recovery_offset(peak, now.duration_since(since).as_secs_f64()),
        }
    }

    /// Apply a write to a defrost register at `now` (phases already settled).
    fn command(&mut self, case: u16, on: bool, now: Instant) {
        let phase = self.phase.get(&case).copied().unwrap_or(Phase::Normal);
        let next = match (phase, on) {
            (Phase::Normal, true) => Phase::Defrost { since: now },
            // Restarting mid-recovery climbs on from the current temperature, so
            // back-date the start to where that offset sits on the climb.
            (Phase::Recovery { since, peak }, true) => {
                let current = recovery_offset(peak, now.duration_since(since).as_secs_f64());
                let back = Duration::from_secs_f64(current as f64 * 4.0);
                Phase::Defrost {
                    since: now.checked_sub(back).unwrap_or(now),
                }
            }
            // Stopping early pulls down from wherever the climb got to.
            (Phase::Defrost { since }, false) => Phase::Recovery {
                since: now,
                peak: rise(now.duration_since(since).as_secs_f64()),
            },
            (p, _) => p,
        };
        self.phase.insert(case, next);
    }
}

pub struct CaseStatus {
    pub temp_tenths: i32,
    pub setpoint_tenths: i32,
    pub defrosting: bool,
}

impl Registers {
    pub fn new() -> Registers {
        let mut rng = rand::thread_rng();
        let mut regs = HashMap::new();
        for case in 0u16..8 {
            let temp = if case < 4 {
                -180 + rng.gen_range(-15..=15)
            } else {
                30 + rng.gen_range(-10..=10)
            };
            regs.insert(case, temp);
            regs.insert(100 + case, if case < 4 { -200 } else { 20 });
            regs.insert(200 + case, 0);
        }
        Registers {
            inner: Mutex::new(RegInner {
                regs,
                phase: HashMap::new(),
            }),
        }
    }

    pub fn mapped(&self, start: u16, count: u16) -> bool {
        if count == 0 || start as u32 + count as u32 > 0x1_0000 {
            return false;
        }
        let g = self.inner.lock().unwrap();
        span(start, count).all(|a| g.regs.contains_key(&a))
    }

    pub fn read(&self, start: u16, count: u16) -> Vec<u16> {
        self.read_at(start, count, Instant::now())
    }

    pub fn read_at(&self, start: u16, count: u16, now: Instant) -> Vec<u16> {
        let mut g = self.inner.lock().unwrap();
        g.settle_all(now);
        let mut rng = rand::thread_rng();
        let mut out = Vec::with_capacity(count as usize);
        for addr in span(start, count) {
            let mut value = *g.regs.get(&addr).unwrap_or(&0);
            if addr < 8 {
                value += rng.gen_range(-2..=2); // sensor jitter
                value += g.offset(addr, now);
            }
            out.push((value & 0xFFFF) as u16);
        }
        out
    }

    pub fn write(&self, start: u16, values: &[u16]) {
        self.write_at(start, values, Instant::now())
    }

    pub fn write_at(&self, start: u16, values: &[u16], now: Instant) {
        let mut g = self.inner.lock().unwrap();
        g.settle_all(now);
        for (offset, &value) in values.iter().enumerate() {
            let addr = start.wrapping_add(offset as u16);
            g.regs.insert(addr, value as i16 as i32);
            if (200..208).contains(&addr) {
                g.command(addr - 200, value != 0, now);
            }
        }
    }

    pub fn case_status(&self) -> Vec<CaseStatus> {
        self.case_status_at(Instant::now())
    }

    pub fn case_status_at(&self, now: Instant) -> Vec<CaseStatus> {
        let temps = self.read_at(0, 8, now);
        let g = self.inner.lock().unwrap();
        (0..8u16)
            .map(|n| CaseStatus {
                temp_tenths: temps[n as usize] as i16 as i32,
                setpoint_tenths: *g.regs.get(&(100 + n)).unwrap_or(&0),
                defrosting: *g.regs.get(&(200 + n)).unwrap_or(&0) != 0,
            })
            .collect()
    }
}

impl Default for Registers {
    fn default() -> Self {
        Self::new()
    }
}

/// Addresses `start..start+count`, computed in u32: a u16 range ending at
/// 0xFFFF+1 saturates to empty, and an empty range passes `all`.
fn span(start: u16, count: u16) -> impl Iterator<Item = u16> {
    let from = start as u32;
    (from..(from + count as u32).min(0x1_0000)).map(|a| a as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    #[test]
    fn registers_reject_ranges_past_the_address_space() {
        let r = Registers::new();
        assert!(r.mapped(0, 8));
        assert!(r.mapped(200, 8));
        assert!(!r.mapped(0xFFFF, 125));
        assert!(
            !r.mapped(0xFFFF, 1),
            "last address is unmapped, not an empty range"
        );
        assert_eq!(span(0xFFFE, 2).collect::<Vec<_>>(), vec![0xFFFE, 0xFFFF]);
        assert_eq!(span(0xFFFF, 1).collect::<Vec<_>>(), vec![0xFFFF]);
        assert!(!r.mapped(0, 0));
        assert!(!r.mapped(8, 1));
    }

    fn temp_at(r: &Registers, case: u16, now: Instant) -> i32 {
        r.read_at(case, 1, now)[0] as i16 as i32
    }

    /// Sensor jitter is ±2 tenths; allow a little more for rounding.
    fn near(got: i32, want: i32) -> bool {
        (got - want).abs() <= 4
    }

    #[test]
    fn defrost_climbs_then_pulls_down_instead_of_snapping_back() {
        let r = Registers::new();
        let base = r.inner.lock().unwrap().regs[&0];
        let t0 = Instant::now();
        let m = |mins: f64| t0 + Duration::from_secs_f64(mins * 60.0);
        r.write_at(200, &[1], t0);
        assert!(r.case_status_at(m(1.0))[0].defrosting);
        assert!(
            near(temp_at(&r, 0, m(10.0)), base + 150),
            "1.5 C/min: +15 C after 10 min"
        );
        assert!(
            near(temp_at(&r, 0, m(20.1)), base + 250),
            "capped at +25 C as the cycle ends"
        );
        assert!(
            !r.case_status_at(m(20.1))[0].defrosting,
            "defrost register clears when the cycle ends"
        );
        assert!(
            near(temp_at(&r, 0, m(20.0 + 22.5)), base + 125),
            "half-way through the 45 min recovery"
        );
        assert!(
            near(temp_at(&r, 0, m(20.0 + 46.0)), base),
            "back to base after recovery"
        );
        assert!(matches!(r.inner.lock().unwrap().phase[&0], Phase::Normal));
    }

    #[test]
    fn stopping_a_defrost_early_recovers_from_where_it_got_to() {
        let r = Registers::new();
        let base = r.inner.lock().unwrap().regs[&1];
        let t0 = Instant::now();
        let m = |mins: f64| t0 + Duration::from_secs_f64(mins * 60.0);
        r.write_at(201, &[1], t0);
        r.write_at(201, &[0], m(4.0)); // +6 C reached, heaters off
        assert!(!r.case_status_at(m(4.0))[1].defrosting);
        assert!(
            near(temp_at(&r, 1, m(4.0)), base + 60),
            "no snap-back when the defrost stops"
        );
        assert!(
            near(temp_at(&r, 1, m(4.0 + 22.5)), base + 30),
            "half of the 6 C gone half-way through"
        );
        assert!(near(temp_at(&r, 1, m(4.0 + 46.0)), base));
    }

    #[test]
    fn phases_advance_on_any_register_access_not_just_temperature_reads() {
        let r = Registers::new();
        let t0 = Instant::now();
        let m = |mins: f64| t0 + Duration::from_secs_f64(mins * 60.0);
        r.write_at(200, &[1], t0);
        assert_eq!(
            r.read_at(200, 1, m(70.0)),
            vec![0],
            "an expired defrost reads 0 from the command register alone"
        );
        r.write_at(200, &[1], m(70.0));
        assert_eq!(
            r.read_at(200, 1, m(70.5)),
            vec![1],
            "a new start after expiry is not lost"
        );
        let base = r.inner.lock().unwrap().regs[&0];
        assert!(
            near(temp_at(&r, 0, m(80.0)), base + 150),
            "and it climbs from base again"
        );
    }

    #[test]
    fn restarting_mid_recovery_climbs_on_from_the_current_temperature() {
        let r = Registers::new();
        let base = r.inner.lock().unwrap().regs[&2];
        let t0 = Instant::now();
        let m = |mins: f64| t0 + Duration::from_secs_f64(mins * 60.0);
        r.write_at(202, &[1], t0);
        r.write_at(202, &[0], m(10.0)); // +15 C
        r.write_at(202, &[1], m(10.0 + 22.5)); // back on at +7.5 C
        assert!(
            near(temp_at(&r, 2, m(32.5)), base + 75),
            "restart continues from +7.5 C, not from base"
        );
        assert!(
            near(temp_at(&r, 2, m(32.5 + 5.0)), base + 150),
            "and climbs 1.5 C/min from there"
        );
    }

    #[test]
    fn slots_cap_per_ip_and_free_on_drop() {
        let cfg = Config::from_env().unwrap();
        let slots = Arc::new(Slots::new(&cfg));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let held: Vec<SlotGuard> = (0..cfg.max_per_ip).map(|_| slots.take(ip).unwrap()).collect();
        assert!(slots.take(ip).is_none(), "per-IP cap");
        assert!(
            slots.take(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))).is_some(),
            "other sources unaffected"
        );
        drop(held);
        assert!(slots.take(ip).is_some(), "freed on drop");
    }

    #[test]
    fn sessions_validate_only_issued_tokens() {
        let s = Sessions::new(&Config::from_env().unwrap());
        let t = s.new_token();
        assert_eq!(t.len(), 64);
        assert!(s.valid(&t));
        assert!(!s.valid(""));
        assert!(!s.valid("nope"));
    }

    #[test]
    fn a_flood_of_logins_evicts_the_oldest_sessions_not_all_of_them() {
        let s = Sessions::new(&Config::from_env().unwrap());
        let tokens: Vec<String> = (0..MAX_SESSIONS + 100).map(|_| s.new_token()).collect();
        assert!(tokens[..100].iter().all(|t| !s.valid(t)), "the oldest are gone");
        assert!(
            tokens[100..].iter().all(|t| s.valid(t)),
            "everyone else keeps their session"
        );
    }
}
