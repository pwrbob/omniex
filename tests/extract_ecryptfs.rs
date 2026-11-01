//! eCryptfs version 2 wrapped-passphrase extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/ecryptfs")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes(
        "wrapped-passphrase",
        std::fs::read(fixture("wrapped-passphrase")).unwrap(),
    )
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn ecryptfs_probe_requires_version_two_and_a_signature() {
    let extractor = extract::by_slug("ecryptfs").expect("eCryptfs extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "eCryptfs version 2 wrapped passphrase"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("v1", b"abcdef1234567890".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("short", b":\x02".to_vec())),
        Probe::No
    );
}

#[test]
fn ecryptfs_extracts_the_wrapped_passphrase() {
    let extractor = extract::by_slug("ecryptfs").expect("eCryptfs extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("wrapped-passphrase.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(12200)));
    assert!(hashes[0].modes().contains(&Mode::John("eCryptfs")));
}

#[test]
fn ecryptfs_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("wrapped-passphrase"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("wrapped-passphrase"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "ecryptfs");
}

#[test]
fn ecryptfs_rejects_bad_signature_hex() {
    let extractor = extract::by_slug("ecryptfs").expect("eCryptfs extractor");
    let mut data = std::fs::read(fixture("wrapped-passphrase")).unwrap();
    data[10..26].copy_from_slice(b"zzzzzzzzzzzzzzzz");
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad", data))
            .is_err()
    );
}
