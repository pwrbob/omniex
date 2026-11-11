//! Extraction fixtures for PFX, PEM, JKS, OpenSSH, and PuTTY keys.

#[path = "../src/extract/diskcryptor.rs"]
mod diskcryptor;
#[path = "../src/extract/jks_private_key.rs"]
mod jks_private_key;
#[path = "../src/extract/luks_v1.rs"]
mod luks_v1;
#[path = "../src/extract/luks_v2.rs"]
mod luks_v2;
#[path = "../src/extract/pem_private_key.rs"]
mod pem_private_key;
#[path = "../src/extract/pfx.rs"]
mod pfx;
#[path = "../src/extract/putty.rs"]
mod putty;
#[path = "../src/extract/sshng.rs"]
mod sshng;
#[path = "../src/extract/truecrypt.rs"]
mod truecrypt;
#[path = "../src/extract/veracrypt.rs"]
mod veracrypt;

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, ExtractError, Extractor, Probe, Selection, select};
use omniex::{Mode, RenderOptions, Tool};

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
static LUKS_V1: luks_v1::LuksV1Extractor = luks_v1::LuksV1Extractor;
static LUKS_V2: luks_v2::LuksV2Extractor = luks_v2::LuksV2Extractor;
static TRUECRYPT: truecrypt::TrueCryptExtractor = truecrypt::TrueCryptExtractor;
static VERACRYPT: veracrypt::VeraCryptExtractor = veracrypt::VeraCryptExtractor;
static DISKCRYPTOR: diskcryptor::DiskcryptorExtractor = diskcryptor::DiskcryptorExtractor;

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

    let cbc = artifact("sshng", "aes256-cbc.key");
    let cbc_hashes: Vec<String> = SSHNG
        .extract(&cbc)
        .expect("extract")
        .iter()
        .map(|value| {
            value
                .render(&RenderOptions {
                    tool: Tool::John,
                    ..RenderOptions::default()
                })
                .unwrap()
        })
        .collect();
    assert_eq!(cbc_hashes, [expected("sshng", "aes256-cbc.hash")]);
    assert!(modes(&SSHNG, &cbc).contains(&Mode::John("SSH")));
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

#[test]
fn luks_v1_extracts_every_active_keyslot() {
    let volume = artifact("luks-v1", "volume.img");
    assert!(matches!(LUKS_V1.probe(&volume), Probe::Yes(_)));
    assert_eq!(
        render(&LUKS_V1, &volume),
        [
            expected("luks-v1", "slot1.hash"),
            expected("luks-v1", "slot2.hash"),
        ]
    );
    assert_eq!(modes(&LUKS_V1, &volume), [Mode::Hashcat(29521)]);
}

#[test]
fn luks_v1_rejects_other_versions_and_malformed_headers() {
    let v2 = artifact("luks-v2", "volume.img");
    assert_eq!(LUKS_V1.probe(&v2), Probe::No);
    assert!(matches!(
        extract_error(&LUKS_V1, &v2),
        ExtractError::Unsupported(_)
    ));

    for name in ["empty.img", "truncated.img", "random.bin"] {
        let artifact = artifact("luks-v1", name);
        assert_eq!(LUKS_V1.probe(&artifact), Probe::No, "{name}");
        assert!(LUKS_V1.extract(&artifact).is_err(), "{name}");
    }
}

#[test]
fn luks_v2_extracts_every_keyslot() {
    let volume = artifact("luks-v2", "volume.img");
    assert!(matches!(LUKS_V2.probe(&volume), Probe::Yes(_)));
    assert_eq!(
        render(&LUKS_V2, &volume),
        [
            expected("luks-v2", "slot0.hash"),
            expected("luks-v2", "slot1.hash"),
        ]
    );
    assert_eq!(modes(&LUKS_V2, &volume), [Mode::Hashcat(34100)]);
}

#[test]
fn luks_v2_rejects_other_versions_and_malformed_headers() {
    let v1 = artifact("luks-v1", "volume.img");
    assert_eq!(LUKS_V2.probe(&v1), Probe::No);
    assert!(matches!(
        extract_error(&LUKS_V2, &v1),
        ExtractError::Unsupported(_)
    ));

    for name in ["empty.img", "truncated.img", "random.bin"] {
        let artifact = artifact("luks-v2", name);
        assert_eq!(LUKS_V2.probe(&artifact), Probe::No, "{name}");
        assert!(LUKS_V2.extract(&artifact).is_err(), "{name}");
    }
}

#[test]
fn truecrypt_extracts_the_volume_header_without_autodetection() {
    let volume = artifact("truecrypt", "volume.img");
    assert!(!TRUECRYPT.exact());
    assert!(matches!(TRUECRYPT.probe(&volume), Probe::Maybe(_)));
    assert_eq!(
        render(&TRUECRYPT, &volume),
        [expected("truecrypt", "volume.hash")]
    );
    assert!(matches!(
        select(&[&TRUECRYPT, &VERACRYPT], &volume),
        Selection::Unconfirmed(candidates) if candidates.len() == 2
    ));

    for name in ["empty.img", "truncated.img"] {
        let artifact = artifact("truecrypt", name);
        assert_eq!(TRUECRYPT.probe(&artifact), Probe::No, "{name}");
        assert!(TRUECRYPT.extract(&artifact).is_err(), "{name}");
    }
}

#[test]
fn veracrypt_extracts_the_volume_header_without_autodetection() {
    let volume = artifact("veracrypt", "volume.img");
    assert!(!VERACRYPT.exact());
    assert!(matches!(VERACRYPT.probe(&volume), Probe::Maybe(_)));
    assert_eq!(
        render(&VERACRYPT, &volume),
        [expected("veracrypt", "volume.hash")]
    );

    for name in ["empty.img", "truncated.img"] {
        let artifact = artifact("veracrypt", name);
        assert_eq!(VERACRYPT.probe(&artifact), Probe::No, "{name}");
        assert!(VERACRYPT.extract(&artifact).is_err(), "{name}");
    }
}

#[test]
fn diskcryptor_extracts_the_volume_header_without_autodetection() {
    let volume = artifact("diskcryptor", "volume.img");
    assert!(!DISKCRYPTOR.exact());
    assert!(matches!(DISKCRYPTOR.probe(&volume), Probe::Maybe(_)));
    assert_eq!(
        render(&DISKCRYPTOR, &volume),
        [expected("diskcryptor", "volume.hash")]
    );
    assert!(matches!(
        select(&[&DISKCRYPTOR], &volume),
        Selection::Unconfirmed(candidates) if candidates.len() == 1
    ));

    for name in ["empty.img", "truncated.img"] {
        let artifact = artifact("diskcryptor", name);
        assert_eq!(DISKCRYPTOR.probe(&artifact), Probe::No, "{name}");
        assert!(DISKCRYPTOR.extract(&artifact).is_err(), "{name}");
    }
}
