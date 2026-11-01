//! OpenBSD softraid crypto extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/openbsd-softraid")
        .join(name)
}

fn artifact(name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(name)).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn softraid_probe_requires_the_raid_type_and_layout() {
    let extractor = extract::by_slug("openbsd-softraid").expect("softraid extractor");
    for name in ["pbkdf2.img", "bcrypt.img"] {
        assert!(matches!(
            extractor.probe(&artifact(name)),
            Probe::Yes(reason) if reason == "OpenBSD softraid crypto metadata"
        ));
    }
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", vec![0; 4096])),
        Probe::No
    );
}

#[test]
fn softraid_extracts_both_kdfs() {
    let extractor = extract::by_slug("openbsd-softraid").expect("softraid extractor");
    for (name, mode) in [
        ("pbkdf2.img", Mode::Hashcat(38800)),
        ("bcrypt.img", Mode::Hashcat(38810)),
    ] {
        let hashes = extractor.extract(&artifact(name)).expect("extract");
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0]
                .render(&RenderOptions {
                    tool: Tool::John,
                    ..RenderOptions::default()
                })
                .unwrap(),
            std::fs::read_to_string(fixture(&name.replace(".img", ".hash")))
                .unwrap()
                .trim_end()
        );
        assert!(hashes[0].modes().contains(&mode));
    }
}

#[test]
fn softraid_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("pbkdf2.img"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("pbkdf2.img"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "openbsd-softraid");
}

#[test]
fn softraid_rejects_invalid_type_kdf_and_truncation() {
    let extractor = extract::by_slug("openbsd-softraid").expect("softraid extractor");
    let data = std::fs::read(fixture("pbkdf2.img")).unwrap();

    let mut wrong_type = data.clone();
    wrong_type[72] = b'X';
    assert!(
        extractor
            .extract(&Artifact::from_bytes("type", wrong_type))
            .is_err()
    );

    let mut wrong_kdf = data.clone();
    wrong_kdf[2416..2420].copy_from_slice(&9u32.to_le_bytes());
    assert!(
        extractor
            .extract(&Artifact::from_bytes("kdf", wrong_kdf))
            .is_err()
    );

    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..2000].to_vec()))
            .is_err()
    );
}
