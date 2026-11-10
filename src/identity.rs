//! Per-deployment identity.
//!
//! A decoy that ships one hard-coded store name, MAC address and CA subject looks
//! identical in every deployment and can be catalogued by anyone doing honeypot
//! detection. Here each identity
//! is derived from a seed: random by default (a fresh identity per start), or
//! fixed if you set `IDENTITY_SEED`, so a deployment can keep a stable identity
//! across restarts without sharing it with anyone else's deployment.

use crate::config::{Config, Persona};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Clone, Debug)]
pub struct Identity {
    pub store_name: String,
    pub hostname: String,
    pub mac: String,
    pub firmware: String,
    pub ca_subject: String,
    pub leaf_subject: String,
    /// Unix time the firmware's static files were "built" (nginx Last-Modified).
    pub firmware_mtime: u64,
}

/// Stable 64-bit hash of an arbitrary string (FNV-1a).
fn fnv1a(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    })
}

fn seeded_rng() -> StdRng {
    match std::env::var("IDENTITY_SEED").ok().filter(|s| !s.is_empty()) {
        Some(s) => StdRng::seed_from_u64(fnv1a(&s)),
        None => StdRng::from_entropy(),
    }
}

/// A function of the firmware string, so two units on the same build advertise
/// the same Last-Modified and different builds differ, as a real fleet does.
fn firmware_mtime(firmware: &str) -> u64 {
    // Deliberately simple: fixed window 2024-06-01 + 0..700 days; widen when the firmware bands move on.
    const WINDOW_START: u64 = 1_717_200_000;
    const WINDOW_SECS: u64 = 700 * 86_400;
    WINDOW_START + fnv1a(firmware) % WINDOW_SECS
}

/// Default OUI per persona, from the IEEE MA-L public registry
/// (standards-oui.ieee.org, retrieved 2026-11-09). Override with MAC_OUI when a
/// real unit shows another.
fn vendor_oui(persona: Persona) -> &'static str {
    match persona {
        // 00-07-68 Danfoss A/S
        Persona::Danfoss | Persona::Aksc355 => "00:07:68",
        // 00-0A-F6 Copeland LP: the prefix a real XWEB 500 EVO shows on its
        // login page, and Copeland's block in the IEEE registry.
        Persona::Dixell => "00:0a:f6",
        // 00-0A-5C Carel s.p.a.
        Persona::Carel => "00:0a:5c",
        // 00-18-BB Eliwell Controls srl. TelevisGo runs on a PC whose NIC may
        // carry its maker's OUI instead; this persona never exposes the MAC.
        Persona::Eliwell => "00:18:bb",
        // 00-05-BC Resource Data Management Ltd
        Persona::Rdm => "00:05:bc",
    }
}

/// Language of the generated banner: STORE_LANG if set, else a guess from the
/// time zone (a unit "in Rome" is more likely Italian than English).
fn banner_lang(cfg: &Config) -> String {
    if let Some(l) = &cfg.store_lang {
        return l.clone();
    }
    match cfg.device_tz.name() {
        "Europe/Rome" | "Europe/Vatican" | "Europe/San_Marino" => "it",
        "Europe/Berlin" | "Europe/Vienna" | "Europe/Zurich" | "Europe/Busingen" => "de",
        "Europe/Paris" | "Europe/Brussels" | "Europe/Luxembourg" | "Europe/Monaco" => "fr",
        "Europe/Madrid" => "es",
        "Europe/Amsterdam" => "nl",
        _ => "en",
    }
    .to_string()
}

/// Plausible, generic grocery banners per language. Generic on purpose: real
/// chain names would impersonate a business and give every deployment a shared
/// catalogue key. Operators who want a real banner set STORE_NAME.
fn store_banners(lang: &str) -> &'static [&'static str] {
    match lang {
        "it" => &[
            "Supermercato Centrale",
            "Alimentari Rossi",
            "Market Nord",
            "Minimarket Via Roma",
            "Ipermercato Sud",
            "Discount Primavera",
            "Fresco Market",
            "Superstore Aurora",
            "Mercato del Borgo",
            "Spesa Facile",
        ],
        "de" => &[
            "Frischmarkt Mitte",
            "Nahkauf Nord",
            "Supermarkt am Bahnhof",
            "Lebensmittel Weber",
            "Markt an der Linde",
            "Frische Ecke",
            "City Markt",
            "Getränkemarkt Süd",
            "Biomarkt Linde",
            "Discount Nord",
        ],
        "fr" => &[
            "Supermarché Central",
            "Épicerie du Marché",
            "Marché Frais",
            "Alimentation Nord",
            "Supérette du Centre",
            "Proxi Village",
            "Marché du Parc",
            "Hyper Sud",
            "Épicerie Bleue",
            "Frais Quotidien",
        ],
        "es" => &[
            "Supermercado Central",
            "Alimentación Norte",
            "Mercado Fresco",
            "Ultramarinos López",
            "Autoservicio Sur",
            "Super Ahorro",
            "Hiper Plaza",
            "Mercado del Barrio",
            "Frutas y Más",
            "Tienda Diaria",
        ],
        "nl" => &[
            "Buurtsuper Centrum",
            "Versmarkt Noord",
            "Supermarkt De Linde",
            "Dagwinkel Zuid",
            "Vers & Zo",
            "Markt aan de Gracht",
            "Boodschappen Plus",
            "Super Oost",
            "Vershuis",
            "Koopcentrum",
        ],
        _ => &[
            "Fresh Market",
            "City Foods",
            "Green Valley",
            "Market Hall",
            "Corner Store",
            "Food Centre",
            "Daily Fresh",
            "Prime Grocers",
            "Riverside Market",
            "Hillview Foods",
        ],
    }
}

impl Identity {
    pub fn generate(cfg: &Config) -> Identity {
        let mut rng = seeded_rng();
        let site: u16 = rng.gen_range(100..9999);

        let store_name = cfg.store_name.clone().unwrap_or_else(|| {
            let banners = store_banners(&banner_lang(cfg));
            format!("{} {site:04}", banners[rng.gen_range(0..banners.len())])
        });

        // MAC: the vendor's OUI (operator override first) + three random octets.
        let oui = cfg.mac_oui.as_deref().unwrap_or_else(|| vendor_oui(cfg.persona));
        let mac = format!(
            "{oui}:{:02x}:{:02x}:{:02x}",
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>()
        );

        let firmware = cfg.firmware.clone().unwrap_or_else(|| match cfg.persona {
            // A single build string, reused everywhere it appears, so the login
            // page and the XML API never disagree (a classic tell).
            Persona::Danfoss => {
                let build = rng.gen_range(120..200);
                format!("SVB501.000.{build:03}")
            }
            // One real XWEB 500 EVO was seen on 5.8.8; stay within that line.
            Persona::Dixell => {
                let patch = rng.gen_range(0..=8);
                format!("5.8.{patch}")
            }
            // AK-SC 355 front-end is documented as "3.091 or higher".
            Persona::Aksc355 => {
                let build = rng.gen_range(91..200);
                format!("3.{build:03}")
            }
            // Carel pCOWeb application version, documented like "A 1.4.11 - B 1.4.2".
            Persona::Carel => {
                let a = rng.gen_range(5..20);
                let b = rng.gen_range(0..9);
                format!("A 1.4.{a} - B 1.4.{b}")
            }
            // Eliwell TelevisGo software version, e.g. 5.0.0.0.
            Persona::Eliwell => {
                let minor = rng.gen_range(0..4);
                format!("5.{minor}.0.0")
            }
            // RDM Data Manager application version (v2.x line of the CVE era).
            Persona::Rdm => {
                let minor = rng.gen_range(1..6);
                let patch = rng.gen_range(0..40);
                format!("2.{minor}.{patch}")
            }
        });

        let (hostname, ca_subject, leaf_subject) = match cfg.persona {
            Persona::Danfoss => (
                format!("SM800A-{site:04}"),
                "SelfSigned-DanfossSM800A".to_string(),
                "DanfossSM800A".to_string(),
            ),
            Persona::Dixell => (format!("XWEB-{site:04}"), "XWEB".to_string(), "XWEB".to_string()),
            // No certificate is recorded for the AK-SC 355, so a bare model CN:
            // borrowing the AK-SM `SelfSigned-Danfoss…` scheme would be a guess.
            Persona::Aksc355 => (
                format!("AKSC355-{site:04}"),
                "AKSC355".to_string(),
                "AKSC355".to_string(),
            ),
            Persona::Carel => ("pCOWeb".to_string(), "pCOWeb".to_string(), "pCOWeb".to_string()),
            Persona::Eliwell => (
                "TelevisGo".to_string(),
                "TelevisGo".to_string(),
                "TelevisGo".to_string(),
            ),
            Persona::Rdm => (
                format!("DM-{site:04}"),
                "DataManager".to_string(),
                "DataManager".to_string(),
            ),
        };

        let firmware_mtime = firmware_mtime(&firmware);
        Identity {
            store_name,
            hostname,
            mac,
            firmware,
            ca_subject,
            leaf_subject,
            firmware_mtime,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_mtime_is_stable_per_build_and_in_the_past() {
        let a = firmware_mtime("SVB501.000.150");
        assert_eq!(a, firmware_mtime("SVB501.000.150"));
        assert_ne!(a, firmware_mtime("SVB501.000.151"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(
            a > 1_717_200_000 && a < now,
            "mtime {a} should fall in the window"
        );
    }

    #[test]
    fn store_name_follows_store_lang_then_the_time_zone() {
        let mut cfg = Config::from_env().unwrap();
        cfg.store_name = None;
        cfg.store_lang = None;
        for (tz, sample) in [
            (chrono_tz::Europe::Rome, "Supermercato Centrale"),
            (chrono_tz::Europe::Berlin, "Frischmarkt Mitte"),
            (chrono_tz::Europe::London, "Fresh Market"),
        ] {
            cfg.device_tz = tz;
            let banners = store_banners(&banner_lang(&cfg));
            assert!(banners.contains(&sample), "{tz}: list should hold {sample}");
            let name = Identity::generate(&cfg).store_name;
            assert!(
                banners.iter().any(|b| name.starts_with(b)),
                "{tz}: {name:?} not from its list"
            );
        }
        // STORE_LANG overrides the time-zone guess.
        cfg.device_tz = chrono_tz::Europe::London;
        cfg.store_lang = Some("it".into());
        let name = Identity::generate(&cfg).store_name;
        assert!(
            store_banners("it").iter().any(|b| name.starts_with(b)),
            "{name:?} should be Italian"
        );
    }

    #[test]
    fn mac_uses_the_vendor_oui_unless_overridden() {
        let mut cfg = Config::from_env().unwrap();
        cfg.mac_oui = None;
        for (persona, oui) in [
            (Persona::Danfoss, "00:07:68"),
            (Persona::Carel, "00:0a:5c"),
            (Persona::Dixell, "00:0a:f6"),
            (Persona::Rdm, "00:05:bc"),
        ] {
            cfg.persona = persona;
            let mac = Identity::generate(&cfg).mac;
            assert!(mac.starts_with(oui), "{persona:?}: {mac} should start with {oui}");
            assert_eq!(mac.len(), 17);
        }
        cfg.mac_oui = Some("aa:bb:cc".into());
        assert!(Identity::generate(&cfg).mac.starts_with("aa:bb:cc"));
    }

    #[test]
    fn fnv1a_distinguishes_inputs() {
        assert_ne!(fnv1a("seed-a"), fnv1a("seed-b"));
        assert_eq!(fnv1a(""), 0xcbf29ce484222325);
    }
}
