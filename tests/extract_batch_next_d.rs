//! Extraction coverage for iWork 2009, eCryptfs version 1, and OpenPGP
//! symmetrically encrypted files.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(slug, name)).unwrap())
}

fn expected(slug: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(slug, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn iwork_2009_probe_and_extract() {
    let extractor = extract::by_slug("iwork").expect("iWork extractor");
    assert!(matches!(
        extractor.probe(&artifact("iwork", "sample-2009.key")),
        Probe::Yes(reason) if reason == "iWork 2009 password verifier"
    ));

    let hashes = extractor
        .extract(&artifact("iwork", "sample-2009.key"))
        .expect("extract iWork 2009");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("iwork", "sample-2009.hash")
    );
}

#[test]
fn iwork_2009_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("iwork", "sample-2009.key"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("iwork", "sample-2009.key"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "iwork");
    assert_eq!(value[0]["hash"], expected("iwork", "sample-2009.hash"));
}

#[test]
fn iwork_2009_rejects_truncated_input() {
    let extractor = extract::by_slug("iwork").expect("iWork extractor");
    let data = std::fs::read(fixture("iwork", "sample-2009.key")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", data[..100].to_vec()))
            .is_err()
    );
}

#[test]
fn ecryptfs_version_one_requires_explicit_type() {
    let extractor = extract::by_slug("ecryptfs").expect("eCryptfs extractor");
    assert_eq!(
        extractor.probe(&artifact("ecryptfs", "wrapped-passphrase-v1")),
        Probe::No
    );

    let hashes = extractor
        .extract(&artifact("ecryptfs", "wrapped-passphrase-v1"))
        .expect("extract eCryptfs v1");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("ecryptfs", "wrapped-passphrase-v1.hash")
    );

    let explicit = omniex()
        .arg("extract")
        .arg(fixture("ecryptfs", "wrapped-passphrase-v1"))
        .args(["--type", "ecryptfs"])
        .output()
        .unwrap();
    assert!(explicit.status.success());

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("ecryptfs", "wrapped-passphrase-v1"))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&all.stdout).contains("$ecryptfs$"));
}

#[test]
fn ecryptfs_version_one_rejects_malformed_input() {
    let extractor = extract::by_slug("ecryptfs").expect("eCryptfs extractor");
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad", b"zzzzzzzzzzzzzzzz".to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", b"short".to_vec()))
            .is_err()
    );
}

#[test]
fn pgp_symmetric_probe_and_extract() {
    let extractor = extract::by_slug("pgp").expect("pgp extractor");
    assert!(matches!(
        extractor.probe(&artifact("pgp", "symmetric.gpg")),
        Probe::Yes(reason) if reason == "OpenPGP symmetrically encrypted file"
    ));

    let hashes = extractor
        .extract(&artifact("pgp", "symmetric.gpg"))
        .expect("extract symmetric OpenPGP");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        expected("pgp", "symmetric.hash")
    );
}

#[test]
fn pgp_symmetric_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("pgp", "symmetric.gpg"))
        .args(["--format", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("pgp", "symmetric.gpg"))
        .args(["--format", "john", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "pgp");
    assert_eq!(value[0]["hash"], expected("pgp", "symmetric.hash"));
}

#[test]
fn pgp_symmetric_rejects_truncated_and_empty_input() {
    let extractor = extract::by_slug("pgp").expect("pgp extractor");
    let data = std::fs::read(fixture("pgp", "symmetric.gpg")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", data[..10].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}
