//! FileZilla Server and Enpass extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, ExtractError, Extracted, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(kind, name)).expect("read artifact"),
    )
}

fn extract_error(result: Result<Extracted, ExtractError>) -> ExtractError {
    match result {
        Ok(_) => panic!("expected extraction to fail"),
        Err(error) => error,
    }
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn filezilla_probe_requires_the_server_xml_root() {
    let extractor = extract::by_slug("filezilla-server").expect("FileZilla extractor");
    assert!(matches!(
        extractor.probe(&artifact("filezilla", "FileZilla Server.xml")),
        Probe::Yes(reason) if reason == "FileZilla Server XML root"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"<other />".to_vec())),
        Probe::No
    );
}

#[test]
fn filezilla_extracts_supported_users() {
    let extractor = extract::by_slug("filezilla-server").expect("FileZilla extractor");
    let hashes = extractor
        .extract(&artifact("filezilla", "FileZilla Server.xml"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("filezilla", "FileZilla Server.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(15000)));
}

#[test]
fn filezilla_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("filezilla", "FileZilla Server.xml"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("filezilla", "FileZilla Server.xml"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "filezilla-server");
}

#[test]
fn filezilla_rejects_malformed_and_unsupported_configs() {
    let extractor = extract::by_slug("filezilla-server").expect("FileZilla extractor");
    let malformed = "<FileZillaServer><Users>";
    assert!(
        extract_error(extractor.extract(&Artifact::from_bytes("bad", malformed.into())))
            .to_string()
            .contains("invalid FileZilla XML")
    );

    let legacy = "<FileZillaServer><Users><User Name=\"x\"><Option Name=\"Pass\">0123456789abcdef0123456789abcdef</Option></User></Users></FileZillaServer>";
    assert!(
        extract_error(extractor.extract(&Artifact::from_bytes("legacy", legacy.into())))
            .to_string()
            .contains("no supported FileZilla Server hashes")
    );

    let bad_hex = "<FileZillaServer><Users><User Name=\"x\"><Option Name=\"Pass\">zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz</Option><Option Name=\"Salt\">01234567890123456789012345678901</Option></User></Users></FileZillaServer>";
    assert!(
        extract_error(extractor.extract(&Artifact::from_bytes("bad-hex", bad_hex.into())))
            .to_string()
            .contains("invalid FileZilla digest")
    );
}

#[test]
fn enpass_probe_uses_only_the_file_extension() {
    let extractor = extract::by_slug("enpass").expect("Enpass extractor");
    assert!(matches!(
        extractor.probe(&artifact("enpass", "test.enpassdb")),
        Probe::Maybe(reason) if reason.contains("extension")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("test.bin", vec![1, 2, 3])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty.enpassdb", Vec::new())),
        Probe::No
    );
}

#[test]
fn enpass_extracts_the_first_kibibyte_for_john() {
    let extractor = extract::by_slug("enpass").expect("Enpass extractor");
    let hashes = extractor
        .extract(&artifact("enpass", "test.enpassdb"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("enpass", "test.enpassdb.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("enpass")));
}

#[test]
fn enpass_requires_an_explicit_type_in_the_cli() {
    let automatic = omniex()
        .arg("extract")
        .arg(fixture("enpass", "test.enpassdb"))
        .output()
        .unwrap();
    assert_eq!(automatic.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&automatic.stderr).contains("has no reliable signature"));

    let explicit = omniex()
        .args(["extract", "--type", "enpass", "--tool", "john"])
        .arg(fixture("enpass", "test.enpassdb"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8(explicit.stdout).unwrap().trim_end(),
        std::fs::read_to_string(fixture("enpass", "test.enpassdb.hash"))
            .unwrap()
            .trim_end()
    );
}

#[test]
fn enpass_short_and_empty_files_are_handled() {
    let extractor = extract::by_slug("enpass").expect("Enpass extractor");
    let short = Artifact::from_bytes("short.enpassdb", vec![0xaa, 0xbb]);
    let hashes = extractor.extract(&short).unwrap();
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        "$enpass$1$100000$aabb"
    );

    let empty = Artifact::from_bytes("empty.enpassdb", Vec::new());
    let error = extract_error(extractor.extract(&empty));
    assert!(error.to_string().contains("empty"));
}
