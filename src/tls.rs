//! Self-signed certificate generation.
//!
//! Follows what scanners record for real AK-SM 800A units: a
//! `SelfSigned-DanfossSM800A`-style CA and a one-year leaf. Validity is
//! backdated by a random amount so the certificate never reveals when the decoy
//! was built, and keys are fresh each start, so two deployments never share one.
//! Generated in-process (no openssl shell-out).

use crate::config::{Config, Persona};
use crate::identity::Identity;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

pub struct DecoyCert {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// The certificate to serve: the one kept in `TLS_DIR` if there is one, else a
/// new one, saved there for the next start. A real unit presents the same
/// certificate for months; a fingerprint that changes at every restart is what
/// a scanner comparing two passes notices. Without `TLS_DIR` each start gets a
/// fresh certificate.
pub fn load_or_generate(cfg: &Config, id: &Identity) -> Result<DecoyCert, String> {
    let Some(dir) = &cfg.tls_dir else {
        return generate(cfg, id);
    };
    // Named per persona, so switching PERSONA never serves the old subject.
    let file = |part: &str| dir.join(format!("{}-{part}.der", cfg.persona.as_str()));
    let paths = [file("leaf"), file("ca"), file("key")];
    // Deliberately simple: a kept certificate is reused even past its notAfter, as an
    // unattended unit would; delete the files to roll it.
    if let [Ok(leaf), Ok(ca), Ok(key)] = [&paths[0], &paths[1], &paths[2]].map(std::fs::read) {
        return Ok(DecoyCert {
            cert_chain: vec![CertificateDer::from(leaf), CertificateDer::from(ca)],
            key: PrivateKeyDer::try_from(key).map_err(|e| format!("{}: {e}", paths[2].display()))?,
        });
    }
    let cert = generate(cfg, id)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("TLS_DIR {}: {e}", dir.display()))?;
    // Deliberately simple: default file mode; the key signs nothing but this decoy.
    let blobs = [
        &cert.cert_chain[0][..],
        &cert.cert_chain[1][..],
        cert.key.secret_der(),
    ];
    for (path, blob) in paths.iter().zip(blobs) {
        std::fs::write(path, blob).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(cert)
}

pub fn generate(cfg: &Config, id: &Identity) -> Result<DecoyCert, String> {
    let mut rng = rand::thread_rng();
    use rand::Rng;

    let now = OffsetDateTime::now_utc();
    // CA: issued 2-7 years ago, valid 10 years.
    let ca_start =
        now - Duration::days(rng.gen_range(730..=2555)) - Duration::seconds(rng.gen_range(0..86_400));
    let ca_end = ca_start + Duration::days(3650);
    // Leaf: issued 1-11 months ago, valid 1 year.
    let leaf_start =
        now - Duration::days(rng.gen_range(30..=330)) - Duration::seconds(rng.gen_range(0..86_400));
    let leaf_end = leaf_start + Duration::days(365);

    // --- CA ---
    let ca_key = KeyPair::generate().map_err(|e| format!("ca key: {e}"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = ca_start;
    ca_params.not_after = ca_end;
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        // The full issuer DN is only recorded for AK-SM 800A units. No issuer
        // details are documented for the other personas, so their CA carries
        // its CN alone: a missing detail is a smaller tell than a wrong one.
        if cfg.persona == Persona::Danfoss {
            dn.push(DnType::CountryName, "US");
            dn.push(DnType::StateOrProvinceName, "MD");
            dn.push(DnType::LocalityName, "Baltimore");
            dn.push(DnType::OrganizationName, "Danfoss");
            dn.push(DnType::OrganizationalUnitName, "Certificate_Authority");
        }
        dn.push(DnType::CommonName, id.ca_subject.clone());
        dn
    };
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("ca sign: {e}"))?;

    // --- Leaf ---
    let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
    let mut leaf_params =
        CertificateParams::new(vec![id.leaf_subject.clone()]).map_err(|e| format!("leaf params: {e}"))?;
    leaf_params.not_before = leaf_start;
    leaf_params.not_after = leaf_end;
    leaf_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, id.leaf_subject.clone());
        dn
    };
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("leaf sign: {e}"))?;

    let cert_chain = vec![
        CertificateDer::from(leaf_cert.der().to_vec()),
        CertificateDer::from(ca_cert.der().to_vec()),
    ];
    let key = PrivateKeyDer::try_from(leaf_key.serialize_der()).map_err(|e| format!("leaf key der: {e}"))?;

    Ok(DecoyCert { cert_chain, key })
}

/// Build a rustls server config pinned to TLS 1.2, as the real units serve.
pub fn server_config(cert: DecoyCert) -> Result<Arc<rustls::ServerConfig>, String> {
    let versions: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    let provider = rustls::crypto::ring::default_provider();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| format!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(cert.cert_chain, cert.key)
        .map_err(|e| format!("tls cert: {e}"))?;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_certificate_survives_a_restart_and_a_fresh_one_does_not() {
        let dir = std::env::temp_dir().join(format!("fridgep0t-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::from_env().unwrap();
        let id = Identity::generate(&cfg);
        let leaf = |cfg: &Config| load_or_generate(cfg, &id).unwrap().cert_chain[0].to_vec();

        cfg.tls_dir = None;
        assert_ne!(leaf(&cfg), leaf(&cfg), "no TLS_DIR: fresh certificate each start");

        cfg.tls_dir = Some(dir.clone());
        let first = leaf(&cfg);
        assert_eq!(
            first,
            leaf(&cfg),
            "TLS_DIR: the same certificate on the next start"
        );
        server_config(load_or_generate(&cfg, &id).unwrap()).expect("kept key still loads");

        cfg.persona = Persona::Carel;
        assert_ne!(first, leaf(&cfg), "another persona gets its own certificate");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
