//! Extraction for ZipCrypto, SecureZIP, and RAR3 archives.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(slug, name)).expect("read artifact"),
    )
}

fn expected(slug: &str) -> String {
    std::fs::read_to_string(fixture(slug, "archive.hash"))
        .expect("read expected hash")
        .trim_end()
        .to_owned()
}

fn rendered(hashes: &extract::Extracted) -> Vec<String> {
    hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).expect("render"))
        .collect()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pkzip_probe_requires_a_zipcrypto_entry() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    assert!(matches!(
        extractor.probe(&artifact("pkzip", "archive.zip")),
        Probe::Yes(reason) if reason == "PKZIP ZipCrypto entry"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"PK\x03\x04plain".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn pkzip_extracts_the_entry() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let hashes = extractor
        .extract(&artifact("pkzip", "archive.zip"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("pkzip")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(17210)));
    assert!(!hashes[0].modes().contains(&Mode::Hashcat(17200)));
    assert!(hashes[0].modes().contains(&Mode::Hashcat(17225)));
    assert!(hashes[0].modes().contains(&Mode::John("PKZIP")));
}

#[test]
fn pkzip_keeps_every_entry_in_one_hash() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let mut data = std::fs::read(fixture("pkzip", "archive.zip")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.zip", data))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    let rendered = hashes[0].render(&RenderOptions::default()).unwrap();
    assert!(rendered.starts_with("$pkzip$2*"), "{rendered}");
}

#[test]
fn pkzip_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "archive.zip"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("pkzip", "archive.zip"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "pkzip");
}

#[test]
fn pkzip_rejects_truncated_and_other_formats() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let data = std::fs::read(fixture("pkzip", "archive.zip")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..20].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "securezip",
                std::fs::read(fixture("securezip", "archive.zip")).unwrap()
            ))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
}

#[test]
fn securezip_probe_requires_a_strong_encryption_header() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    assert!(matches!(
        extractor.probe(&artifact("securezip", "archive.zip")),
        Probe::Yes(reason) if reason == "SecureZIP strong-encryption header"
    ));
    assert_eq!(
        extractor.probe(&artifact("pkzip", "archive.zip")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn securezip_extracts_the_entry() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let hashes = extractor
        .extract(&artifact("securezip", "archive.zip"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("securezip")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23003)));
    assert!(hashes[0].modes().contains(&Mode::John("securezip")));
}

#[test]
fn securezip_finds_every_entry() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let mut data = std::fs::read(fixture("securezip", "archive.zip")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.zip", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn securezip_rejects_truncated_and_other_formats() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let data = std::fs::read(fixture("securezip", "archive.zip")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..40].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&artifact("pkzip", "archive.zip"))
            .is_err()
    );
}

#[test]
fn rar3p_probe_requires_a_file_header() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    assert!(matches!(
        extractor.probe(&artifact("rar3p", "archive.rar")),
        Probe::Yes(reason) if reason == "RAR3 encrypted file header"
    ));
    assert_eq!(
        extractor.probe(&artifact("rar3hp", "archive.rar")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a rar".to_vec())),
        Probe::No
    );
}

#[test]
fn rar3p_extracts_the_entry() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let hashes = extractor
        .extract(&artifact("rar3p", "archive.rar"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("rar3p")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23700)));
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23800)));
}

#[test]
fn rar3p_finds_hashes_in_later_archives() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let mut data = std::fs::read(fixture("rar3p", "archive.rar")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.rar", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn rar3p_rejects_truncated_archives() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let data = std::fs::read(fixture("rar3p", "archive.rar")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..30].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
}

#[test]
fn rar3hp_probe_requires_an_encrypted_header() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    assert!(matches!(
        extractor.probe(&artifact("rar3hp", "archive.rar")),
        Probe::Yes(reason) if reason == "RAR3 encrypted header"
    ));
    assert_eq!(
        extractor.probe(&artifact("rar3p", "archive.rar")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn rar3hp_extracts_the_trailer() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    let hashes = extractor
        .extract(&artifact("rar3hp", "archive.rar"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("rar3hp")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(12500)));
    assert!(hashes[0].modes().contains(&Mode::John("rar")));
}

#[test]
fn rar3hp_rejects_truncated_and_plain_archives() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    let data = std::fs::read(fixture("rar3hp", "archive.rar")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..20].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&artifact("rar3p", "archive.rar"))
            .is_err()
    );
}

#[test]
fn rar3_archives_are_disambiguated_by_header_encryption() {
    let rar3p = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let rar3hp = extract::by_slug("rar3hp").expect("RAR3-hp extractor");

    assert!(matches!(
        rar3p.probe(&artifact("rar3p", "archive.rar")),
        Probe::Yes(_)
    ));
    assert_eq!(rar3hp.probe(&artifact("rar3p", "archive.rar")), Probe::No);

    assert!(matches!(
        rar3hp.probe(&artifact("rar3hp", "archive.rar")),
        Probe::Yes(_)
    ));
    assert_eq!(rar3p.probe(&artifact("rar3hp", "archive.rar")), Probe::No);
}
