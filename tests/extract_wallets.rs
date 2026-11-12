//! Ethereum, Blockchain, and Electrum wallet extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join("wallet.json")
}

fn artifact(kind: &str) -> Artifact {
    Artifact::from_bytes("wallet.json", std::fs::read(fixture(kind)).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn wallet_probes_select_the_right_variant() {
    for (kind, slug) in [
        ("ethereum-pbkdf2", "ethereum-pbkdf2"),
        ("ethereum-scrypt", "ethereum-scrypt"),
        ("ethereum-presale", "ethereum-presale"),
        ("blockchain", "blockchain"),
        ("electrum", "electrum"),
    ] {
        let extractor = extract::by_slug(slug).expect("wallet extractor");
        assert!(
            matches!(extractor.probe(&artifact(kind)), Probe::Yes(_)),
            "{kind}"
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("bad", b"not json".to_vec())),
            Probe::No
        );
    }
}

#[test]
fn wallet_extractors_match_their_fixtures() {
    for (kind, slug, mode) in [
        ("ethereum-pbkdf2", "ethereum-pbkdf2", Mode::Hashcat(15600)),
        ("ethereum-scrypt", "ethereum-scrypt", Mode::Hashcat(15700)),
        ("ethereum-presale", "ethereum-presale", Mode::Hashcat(16300)),
        ("blockchain", "blockchain", Mode::Hashcat(15200)),
        ("electrum", "electrum", Mode::Hashcat(16600)),
    ] {
        let extractor = extract::by_slug(slug).expect("wallet extractor");
        let hashes = extractor.extract(&artifact(kind)).expect("extract");
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0].render(&RenderOptions::default()).unwrap(),
            std::fs::read_to_string(fixture(kind).with_file_name("wallet.hash"))
                .unwrap()
                .trim_end()
        );
        assert!(hashes[0].modes().contains(&mode), "{slug}");
    }
}

#[test]
fn wallet_files_auto_detect_and_report_json() {
    for (kind, slug) in [
        ("ethereum-pbkdf2", "ethereum-pbkdf2"),
        ("ethereum-scrypt", "ethereum-scrypt"),
        ("ethereum-presale", "ethereum-presale"),
        ("blockchain", "blockchain"),
        ("electrum", "electrum"),
    ] {
        let auto = omniex().arg("extract").arg(fixture(kind)).output().unwrap();
        assert!(auto.status.success(), "{kind}");

        let json = omniex()
            .arg("extract")
            .arg("--all")
            .arg(fixture(kind))
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(json.status.success(), "{kind}");
        let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(value[0]["type"], slug);
    }
}

#[test]
fn wallet_extractors_reject_wrong_variants_and_bad_fields() {
    let scrypt = extract::by_slug("ethereum-scrypt").expect("scrypt extractor");
    assert!(scrypt.extract(&artifact("ethereum-pbkdf2")).is_err());
    let pbkdf2 = extract::by_slug("ethereum-pbkdf2").expect("pbkdf2 extractor");
    assert!(pbkdf2.extract(&artifact("ethereum-scrypt")).is_err());
    let electrum = extract::by_slug("electrum").expect("Electrum extractor");
    assert!(
        electrum
            .extract(&Artifact::from_bytes(
                "bad.json",
                b"{\"use_encryption\":false}".to_vec()
            ))
            .is_err()
    );
}
