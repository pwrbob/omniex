//! FreeBSD GELI metadata extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/geli")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("sample.img", std::fs::read(fixture("sample.img")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn geli_probe_requires_metadata_in_the_last_kibibyte() {
    let extractor = extract::by_slug("geli").expect("GELI extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "GELI metadata"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", vec![0; 4096])),
        Probe::No
    );
}

#[test]
fn geli_extracts_metadata_fields() {
    let extractor = extract::by_slug("geli").expect("GELI extractor");
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
    assert!(hashes[0].modes().contains(&Mode::Hashcat(38700)));
    assert!(hashes[0].modes().contains(&Mode::John("geli")));
}

#[test]
fn geli_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.img"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("sample.img"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "geli");
}

#[test]
fn geli_rejects_unsupported_and_truncated_metadata() {
    let extractor = extract::by_slug("geli").expect("GELI extractor");
    let data = std::fs::read(fixture("sample.img")).unwrap();

    let mut bad_ealgo = data.clone();
    bad_ealgo[3200 + 24] = 99;
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad", bad_ealgo))
            .is_err()
    );

    let truncated = data[..3300].to_vec();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", truncated))
            .is_err()
    );
}
