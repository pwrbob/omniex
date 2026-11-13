//! WinZip AES ZIP extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/winzip")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("aes.zip", std::fs::read(fixture("aes.zip")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn winzip_probe_requires_an_aes_entry() {
    let extractor = extract::by_slug("winzip").expect("WinZip extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "WinZip AES entry"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", b"PK\x03\x04".to_vec())),
        Probe::No
    );
}

#[test]
fn winzip_extracts_the_entry() {
    let extractor = extract::by_slug("winzip").expect("WinZip extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("aes.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(13600)));
    assert!(hashes[0].modes().contains(&Mode::John("ZIP")));
}

#[test]
fn winzip_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("aes.zip"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("aes.zip"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["results"][0]["type"], "winzip");
}

#[test]
fn winzip_rejects_truncated_and_plain_archives() {
    let extractor = extract::by_slug("winzip").expect("WinZip extractor");
    let data = std::fs::read(fixture("aes.zip")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..30].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("plain", b"PK\x03\x04plain".to_vec()))
            .is_err()
    );
}
