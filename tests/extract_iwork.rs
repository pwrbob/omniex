//! Apple iWork password verifier extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/iwork")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("sample.key", std::fs::read(fixture("sample.key")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn iwork_probe_requires_a_password_verifier() {
    let extractor = extract::by_slug("iwork").expect("iWork extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "iWork password verifier"
    ));

    let plain = scratch_zip("plain.key", &[("Index/Document.iwa", b"data")]);
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain.key", plain)),
        Probe::No
    );
}

fn scratch_zip(name: &str, entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    let mut data = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut data);
        for (path, content) in entries {
            zip.start_file(*path, SimpleFileOptions::default()).unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap();
    }
    let _ = name;
    data.into_inner()
}

#[test]
fn iwork_extracts_the_verifier() {
    let extractor = extract::by_slug("iwork").expect("iWork extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23300)));
    assert!(hashes[0].modes().contains(&Mode::John("iwork")));
}

#[test]
fn iwork_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.key"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("sample.key"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "iwork");
}

#[test]
fn iwork_rejects_bad_verifier_versions_and_lengths() {
    let extractor = extract::by_slug("iwork").expect("iWork extractor");
    let mut verifier = [0u8; 104];
    verifier[0..2].copy_from_slice(&3u16.to_le_bytes());
    verifier[2..4].copy_from_slice(&1u16.to_le_bytes());
    let data = scratch_zip("bad.key", &[("x.iwpv2", &verifier)]);
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad.key", data))
            .is_err()
    );

    let short = scratch_zip("short.key", &[("x.iwpv2", &[0u8; 50])]);
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short.key", short))
            .is_err()
    );
}
