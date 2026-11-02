//! Extraction fixtures for PFX, PEM, JKS, OpenSSH, and PuTTY keys.

#[path = "../src/extract/jks_private_key.rs"]
mod jks_private_key;
#[path = "../src/extract/pem_private_key.rs"]
mod pem_private_key;
#[path = "../src/extract/pfx.rs"]
mod pfx;
#[path = "../src/extract/putty.rs"]
mod putty;
#[path = "../src/extract/sshng.rs"]
mod sshng;

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, ExtractError, Extractor, Probe, Selection, select};
use omniex::{Mode, RenderOptions};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn render(extractor: &dyn Extractor, artifact: &Artifact) -> Vec<String> {
    extractor
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|value| value.render(&RenderOptions::default()).unwrap())
        .collect()
}

fn extract_error(extractor: &dyn Extractor, artifact: &Artifact) -> ExtractError {
    match extractor.extract(artifact) {
        Ok(_) => panic!("extraction unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn modes(extractor: &dyn Extractor, artifact: &Artifact) -> Vec<Mode> {
    extractor
        .extract(artifact)
        .expect("extract")
        .first()
        .expect("one value")
        .modes()
}

static PKCS12: pfx::Pkcs12Extractor = pfx::Pkcs12Extractor;
static PFX_JOHN: pfx::PfxJohnExtractor = pfx::PfxJohnExtractor;
static PEM: pem_private_key::PemPrivateKeyExtractor = pem_private_key::PemPrivateKeyExtractor;
static JKS: jks_private_key::JksPrivateKeyExtractor = jks_private_key::JksPrivateKeyExtractor;
static SSHNG: sshng::SshngExtractor = sshng::SshngExtractor;
static PUTTY: putty::PuttyExtractor = putty::PuttyExtractor;

#[test]
fn select_reports_unique_ambiguous_and_unconfirmed_probes() {
    let pfx = artifact("pfx", "bundle-sha256.p12");
    assert!(matches!(
        select(&[&PKCS12, &PFX_JOHN], &pfx),
        Selection::Ambiguous(candidates) if candidates.len() == 2
    ));
    assert!(matches!(
        select(&[&JKS], &artifact("jks-private-key", "keystore.jks")),
        Selection::Unique(extractor) if extractor.slug() == "jks-private-key"
    ));
    assert!(matches!(
        select(&[&JKS], &artifact("jks-private-key", "keystore.jceks")),
        Selection::Unconfirmed(candidates) if candidates.len() == 1
    ));
    assert!(matches!(
        select(&[&JKS], &artifact("putty", "key.ppk")),
        Selection::None
    ));
}

#[test]
fn pfx_bundles_render_both_serializations() {
    for (bundle, pkcs12, pfx) in [
        ("bundle-sha1.p12", "sha1.pkcs12", "sha1.pfx"),
        ("bundle-sha256.p12", "sha256.pkcs12", "sha256.pfx"),
    ] {
        let artifact = artifact("pfx", bundle);
        assert!(matches!(PKCS12.probe(&artifact), Probe::Yes(_)));
        assert_eq!(render(&PKCS12, &artifact), [expected("pfx", pkcs12)]);
        let john = RenderOptions {
            tool: omniex::Tool::John,
            ..RenderOptions::default()
        };
        let rendered: Vec<String> = PFX_JOHN
            .extract(&artifact)
            .unwrap()
            .iter()
            .map(|value| value.render(&john).unwrap())
            .collect();
        assert_eq!(rendered, [expected("pfx", pfx)]);
    }
}

#[test]
fn pfx_modes_follow_the_mac_digest() {
    let sha1 = artifact("pfx", "bundle-sha1.p12");
    let sha256 = artifact("pfx", "bundle-sha256.p12");
    assert_eq!(modes(&PKCS12, &sha1), [Mode::Hashcat(24430)]);
    assert_eq!(modes(&PKCS12, &sha256), [Mode::Hashcat(24440)]);
    assert_eq!(modes(&PFX_JOHN, &sha1), [Mode::John("pfx")]);
}

#[test]
fn pfx_rejects_unrelated_and_truncated_inputs() {
    for name in ["empty.p12", "truncated.p12", "random.bin"] {
        let artifact = artifact("pfx", name);
        assert_eq!(PKCS12.probe(&artifact), Probe::No, "{name}");
        assert_eq!(PFX_JOHN.probe(&artifact), Probe::No, "{name}");
        assert!(PKCS12.extract(&artifact).is_err(), "{name}");
    }
    let error = extract_error(&PKCS12, &artifact("pfx", "empty.p12"));
    assert!(matches!(
        error,
        ExtractError::Unsupported(_) | ExtractError::Invalid(_)
    ));
}

#[test]
fn pem_private_keys_render_the_modeled_parameters() {
    for (pem, hash) in [
        ("key-sha1.pem", "key-sha1.hash"),
        ("key-sha256.pem", "key-sha256.hash"),
    ] {
        let artifact = artifact("pem-private-key", pem);
        assert!(
            matches!(PEM.probe(&artifact), Probe::Yes(_)),
            "{pem}: {:?}",
            extract_error(&PEM, &artifact)
        );
        assert_eq!(
            render(&PEM, &artifact),
            [expected("pem-private-key", hash)],
            "{pem}"
        );
    }
    let sha1 = artifact("pem-private-key", "key-sha1.pem");
    let sha256 = artifact("pem-private-key", "key-sha256.pem");
    assert_eq!(modes(&PEM, &sha1), [Mode::Hashcat(24410)]);
    assert_eq!(modes(&PEM, &sha256), [Mode::Hashcat(24420)]);
}

#[test]
fn pem_extractor_skips_plain_keys_and_rejects_unsupported_ciphers() {
    let plain = artifact("pem-private-key", "key-plain.pem");
    assert_eq!(PEM.probe(&plain), Probe::No);
    assert!(matches!(
        extract_error(&PEM, &plain),
        ExtractError::Unsupported(_)
    ));

    let des3 = artifact("pem-private-key", "key-des3.pem");
    assert_eq!(PEM.probe(&des3), Probe::No);
    assert!(matches!(
        extract_error(&PEM, &des3),
        ExtractError::Unsupported(_)
    ));

    let empty = artifact("pem-private-key", "empty.pem");
    assert_eq!(PEM.probe(&empty), Probe::No);
    assert!(PEM.extract(&empty).is_err());
}

#[test]
fn jks_extracts_every_private_key_entry() {
    let single = artifact("jks-private-key", "keystore.jks");
    assert!(matches!(JKS.probe(&single), Probe::Yes(_)));
    assert_eq!(
        render(&JKS, &single),
        [expected("jks-private-key", "keystore.hash")]
    );
    assert_eq!(modes(&JKS, &single), [Mode::Hashcat(15500)]);

    let double = artifact("jks-private-key", "keystore-two.jks");
    assert_eq!(
        render(&JKS, &double),
        [
            expected("jks-private-key", "keystore-two-1.hash"),
            expected("jks-private-key", "keystore-two-2.hash"),
        ]
    );
}

#[test]
fn jks_reports_jceks_as_an_unconfirmed_candidate() {
    let jceks = artifact("jks-private-key", "keystore.jceks");
    assert!(matches!(JKS.probe(&jceks), Probe::Maybe(_)));
    assert!(matches!(
        extract_error(&JKS, &jceks),
        ExtractError::Unsupported(_)
    ));
}

#[test]
fn jks_rejects_other_formats_and_truncated_stores() {
    let pem = artifact("pem-private-key", "key-sha1.pem");
    assert_eq!(JKS.probe(&pem), Probe::No);

    for name in ["empty.jks", "truncated.jks", "bad-header.jks"] {
        let artifact = artifact("jks-private-key", name);
        assert_eq!(JKS.probe(&artifact), Probe::No, "{name}");
        assert!(JKS.extract(&artifact).is_err(), "{name}");
    }
}

#[test]
fn sshng_extracts_new_and_legacy_keys() {
    let modern = artifact("sshng", "id_rsa");
    assert!(matches!(SSHNG.probe(&modern), Probe::Yes(_)));
    assert_eq!(render(&SSHNG, &modern), [expected("sshng", "id_rsa.hash")]);
    assert!(modes(&SSHNG, &modern).contains(&Mode::Hashcat(36800)));

    let legacy_rsa = artifact("sshng", "legacy-rsa.pem");
    assert_eq!(
        render(&SSHNG, &legacy_rsa),
        [expected("sshng", "legacy-rsa.hash")]
    );
    assert!(modes(&SSHNG, &legacy_rsa).contains(&Mode::Hashcat(22951)));

    let legacy_ec = artifact("sshng", "legacy-ec.pem");
    assert_eq!(
        render(&SSHNG, &legacy_ec),
        [expected("sshng", "legacy-ec.hash")]
    );
    assert!(modes(&SSHNG, &legacy_ec).contains(&Mode::Hashcat(22931)));
}

#[test]
fn sshng_ignores_unencrypted_keys_and_rejects_bad_input() {
    let plain = artifact("sshng", "id_ed25519_plain");
    assert_eq!(SSHNG.probe(&plain), Probe::No);
    assert!(matches!(
        extract_error(&SSHNG, &plain),
        ExtractError::Unsupported(_)
    ));

    let empty = artifact("sshng", "empty.pem");
    assert_eq!(SSHNG.probe(&empty), Probe::No);
    assert!(SSHNG.extract(&empty).is_err());

    let truncated = artifact("sshng", "truncated.pem");
    assert_eq!(SSHNG.probe(&truncated), Probe::No);
    assert!(SSHNG.extract(&truncated).is_err());
}

#[test]
fn putty_extracts_the_private_blob_and_metadata() {
    let key = artifact("putty", "key.ppk");
    assert!(matches!(PUTTY.probe(&key), Probe::Yes(_)));
    let john = RenderOptions {
        tool: omniex::Tool::John,
        ..RenderOptions::default()
    };
    let rendered: Vec<String> = PUTTY
        .extract(&key)
        .unwrap()
        .iter()
        .map(|value| value.render(&john).unwrap())
        .collect();
    assert_eq!(rendered, [expected("putty", "putty.hash")]);
    assert_eq!(modes(&PUTTY, &key), [Mode::John("PuTTY")]);
}

#[test]
fn putty_ignores_unencrypted_keys() {
    let plain = artifact("putty", "plain.ppk");
    assert_eq!(PUTTY.probe(&plain), Probe::No);
    assert!(matches!(
        extract_error(&PUTTY, &plain),
        ExtractError::Unsupported(_)
    ));

    let empty = artifact("putty", "empty.ppk");
    assert_eq!(PUTTY.probe(&empty), Probe::No);
    assert!(PUTTY.extract(&empty).is_err());
}
