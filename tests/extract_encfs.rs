//! EncFS configuration extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/encfs")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes(
        ".encfs6.xml",
        std::fs::read(fixture(".encfs6.xml")).expect("read configuration"),
    )
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn encfs_probe_requires_a_complete_configuration() {
    let extractor = extract::by_slug("encfs").expect("EncFS extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "EncFS configuration"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "partial",
            b"<config><name>AES</name></config>".to_vec()
        )),
        Probe::No
    );
}

#[test]
fn encfs_extracts_the_configuration() {
    let extractor = extract::by_slug("encfs").expect("EncFS extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("encfs.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("EncFS")));
}

#[test]
fn encfs_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture(".encfs6.xml"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture(".encfs6.xml"))
        .args(["--tool", "john", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "encfs");
}

#[test]
fn encfs_rejects_unsupported_ciphers_and_bad_lengths() {
    let extractor = extract::by_slug("encfs").expect("EncFS extractor");
    let valid = std::fs::read_to_string(fixture(".encfs6.xml")).unwrap();

    let unsupported = valid.replacen("<name>AES</name>", "<name>Blowfish</name>", 1);
    assert!(
        extractor
            .extract(&Artifact::from_bytes("cipher", unsupported.into_bytes()))
            .is_err()
    );

    let bad_len = valid.replacen("<saltLen>20</saltLen>", "<saltLen>21</saltLen>", 1);
    assert!(
        extractor
            .extract(&Artifact::from_bytes("length", bad_len.into_bytes()))
            .is_err()
    );

    let bad_base64 = valid.replacen("<encodedKeyData>", "<encodedKeyData>not-base64", 1);
    assert!(
        extractor
            .extract(&Artifact::from_bytes("base64", bad_base64.into_bytes()))
            .is_err()
    );
}
