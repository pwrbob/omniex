//! Legacy KDE KWallet extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/kwallet")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("legacy.kwl", std::fs::read(fixture("legacy.kwl")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn kwallet_probe_requires_the_magic_and_legacy_layout() {
    let extractor = extract::by_slug("kwallet").expect("KWallet extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "legacy KWallet file"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", b"not a wallet".to_vec())),
        Probe::No
    );

    let mut modern = std::fs::read(fixture("legacy.kwl")).unwrap();
    modern[13] = 1;
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("modern", modern)),
        Probe::No
    );
}

#[test]
fn kwallet_extracts_the_legacy_payload() {
    let extractor = extract::by_slug("kwallet").expect("KWallet extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("legacy.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(36410)));
    assert!(hashes[0].modes().contains(&Mode::John("kwallet")));
}

#[test]
fn kwallet_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("legacy.kwl"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("legacy.kwl"))
        .args(["--tool", "john", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "kwallet");
}

#[test]
fn kwallet_rejects_truncated_and_invalid_sizes() {
    let extractor = extract::by_slug("kwallet").expect("KWallet extractor");
    let data = std::fs::read(fixture("legacy.kwl")).unwrap();
    for len in [12, 16, 20, data.len() - 1] {
        assert!(
            extractor
                .extract(&Artifact::from_bytes("short", data[..len].to_vec()))
                .is_err()
        );
    }
}

#[test]
fn kwallet_extracts_a_modern_salted_wallet_with_its_sidecar() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("modern.kwl"))
        .args(["--type", "kwallet", "--tool", "john"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim_end(),
        std::fs::read_to_string(fixture("modern.hash"))
            .unwrap()
            .trim_end()
    );
}
