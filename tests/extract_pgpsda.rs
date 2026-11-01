//! PGP self-decrypting archive extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/pgpsda")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("sample.sda", std::fs::read(fixture("sample.sda")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pgpsda_probe_requires_a_header_with_a_valid_offset() {
    let extractor = extract::by_slug("pgpsda").expect("PGP SDA extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "PGP SDA header"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", vec![0; 256])),
        Probe::No
    );
}

#[test]
fn pgpsda_extracts_the_header() {
    let extractor = extract::by_slug("pgpsda").expect("PGP SDA extractor");
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
    assert!(hashes[0].modes().contains(&Mode::John("pgpsda")));
}

#[test]
fn pgpsda_extracts_every_valid_header() {
    let extractor = extract::by_slug("pgpsda").expect("PGP SDA extractor");
    let mut data = std::fs::read(fixture("sample.sda")).unwrap();
    let extra = data[100..144].to_vec();
    data.extend_from_slice(&extra);
    let hashes = extractor
        .extract(&Artifact::from_bytes("multi.sda", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn pgpsda_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.sda"))
        .args(["--format", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("sample.sda"))
        .args(["--format", "john", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "pgpsda");
}

#[test]
fn pgpsda_ignores_headers_with_out_of_range_offsets() {
    let extractor = extract::by_slug("pgpsda").expect("PGP SDA extractor");
    let mut data = std::fs::read(fixture("sample.sda")).unwrap();
    data[100 + 6..100 + 10].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad-offset.sda", data))
            .is_err()
    );
}
