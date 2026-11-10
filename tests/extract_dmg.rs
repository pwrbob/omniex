//! Apple DMG encrcdsa v2 extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/dmg")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("sample.dmg", std::fs::read(fixture("sample.dmg")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn dmg_probe_requires_encrcdsa_v2() {
    let extractor = extract::by_slug("dmg-payload").expect("DMG extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "Apple DMG encrcdsa v2 header"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("lazy", b"not a dmg".to_vec())),
        Probe::No
    );
}

#[test]
fn dmg_extracts_the_legacy_john_serialization() {
    let extractor = extract::by_slug("dmg-payload").expect("DMG extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("dmg")));
}

#[test]
fn dmg_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.dmg"))
        .args(["--format", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("sample.dmg"))
        .args(["--format", "john", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "dmg-payload");
}

#[test]
fn dmg_rejects_truncated_and_oversized_parameters() {
    let extractor = extract::by_slug("dmg-payload").expect("DMG extractor");
    let data = std::fs::read(fixture("sample.dmg")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..100].to_vec()))
            .is_err()
    );
    let mut bad_salt = data.clone();
    bad_salt[108..112].copy_from_slice(&40u32.to_be_bytes());
    assert!(
        extractor
            .extract(&Artifact::from_bytes("salt", bad_salt))
            .is_err()
    );
}
