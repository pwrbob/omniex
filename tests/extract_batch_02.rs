//! Extraction tests for RAR5, 7-Zip, Office, and sheet protection artifacts.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

fn fixture(directory: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(directory)
        .join(name)
}

fn artifact(directory: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(directory, name)).unwrap())
}

fn expected_hashes(directory: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(directory, name))
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn extracted(slug: &str, directory: &str, name: &str) -> Vec<String> {
    let extractor = extract::by_slug(slug).expect("extractor is registered");
    extractor
        .extract(&artifact(directory, name))
        .expect("extract")
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect()
}

#[test]
fn rar5_extracts_every_file_record() {
    assert_eq!(
        extracted("rar5", "rar5", "archive.rar"),
        expected_hashes("rar5", "archive.hash")
    );
    assert_eq!(
        extracted("rar5", "rar5", "header.rar"),
        expected_hashes("rar5", "header.hash")
    );
}

#[test]
fn rar5_probe_and_negative_inputs() {
    let extractor = extract::by_slug("rar5").expect("RAR5 extractor");
    assert!(matches!(
        extractor.probe(&artifact("rar5", "archive.rar")),
        Probe::Yes(reason) if reason.contains("RAR5")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a rar".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("rar5", "archive.rar")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..40].to_vec()))
            .is_err()
    );
}

#[test]
fn sevenzip_extracts_the_aes_stream() {
    assert_eq!(
        extracted("sevenzip", "sevenzip", "archive.7z"),
        expected_hashes("sevenzip", "archive.hash")
    );
    assert_eq!(
        extracted("sevenzip", "sevenzip", "header.7z"),
        expected_hashes("sevenzip", "header.hash")
    );
}

#[test]
fn sevenzip_probe_and_negative_inputs() {
    let extractor = extract::by_slug("sevenzip").expect("7-Zip extractor");
    assert!(matches!(
        extractor.probe(&artifact("sevenzip", "archive.7z")),
        Probe::Yes(reason) if reason.contains("7-Zip")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", b"7z\xbc\xaf\x27\x1c".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("sevenzip", "archive.7z")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..32].to_vec()))
            .is_err()
    );
}

#[test]
fn oldoffice_extracts_word_and_excel_verifiers() {
    assert_eq!(
        extracted("oldoffice", "oldoffice", "word.doc"),
        expected_hashes("oldoffice", "word.hash")
    );
    assert_eq!(
        extracted("oldoffice", "oldoffice", "excel.xls"),
        expected_hashes("oldoffice", "excel.hash")
    );
}

#[test]
fn oldoffice_probe_and_negative_inputs() {
    let extractor = extract::by_slug("oldoffice").expect("old Office extractor");
    assert!(matches!(
        extractor.probe(&artifact("oldoffice", "word.doc")),
        Probe::Yes(reason) if reason.contains("Office")
    ));
    assert_eq!(
        extractor.probe(&artifact("office", "standard.docx")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    let data = std::fs::read(fixture("oldoffice", "word.doc")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..600].to_vec()))
            .is_err()
    );
}

#[test]
fn office_extracts_standard_and_agile_verifiers() {
    assert_eq!(
        extracted("office", "office", "standard.docx"),
        expected_hashes("office", "standard.hash")
    );
    assert_eq!(
        extracted("office", "office", "agile-2010.docx"),
        expected_hashes("office", "agile-2010.hash")
    );
    assert_eq!(
        extracted("office", "office", "agile-2013.docx"),
        expected_hashes("office", "agile-2013.hash")
    );
}

#[test]
fn office_probe_and_negative_inputs() {
    let extractor = extract::by_slug("office").expect("Office extractor");
    assert!(matches!(
        extractor.probe(&artifact("office", "standard.docx")),
        Probe::Yes(reason) if reason.contains("EncryptionInfo")
    ));
    assert_eq!(
        extractor.probe(&artifact("oldoffice", "word.doc")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    let data = std::fs::read(fixture("office", "agile-2010.docx")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..700].to_vec()))
            .is_err()
    );
}

#[test]
fn sheet_protection_extracts_every_worksheet() {
    assert_eq!(
        extracted(
            "office2016-sheetprotection",
            "office2016-sheetprotection",
            "sheets.xlsx"
        ),
        expected_hashes("office2016-sheetprotection", "sheets.hash")
    );
}

#[test]
fn sheet_protection_probe_and_negative_inputs() {
    let extractor =
        extract::by_slug("office2016-sheetprotection").expect("sheet protection extractor");
    assert!(matches!(
        extractor.probe(&artifact(
            "office2016-sheetprotection",
            "sheets.xlsx"
        )),
        Probe::Yes(reason) if reason.contains("protection")
    ));
    assert_eq!(
        extractor.probe(&artifact("office", "standard.docx")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    let data = std::fs::read(fixture("office2016-sheetprotection", "sheets.xlsx")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..64].to_vec()))
            .is_err()
    );
}

#[test]
fn cli_auto_detects_and_selects_by_type() {
    for (directory, name, slug) in [
        ("rar5", "header.rar", "rar5"),
        ("sevenzip", "archive.7z", "sevenzip"),
        ("oldoffice", "word.doc", "oldoffice"),
        ("office", "standard.docx", "office"),
        (
            "office2016-sheetprotection",
            "sheets.xlsx",
            "office2016-sheetprotection",
        ),
    ] {
        let auto = omniex()
            .arg("extract")
            .arg(fixture(directory, name))
            .output()
            .unwrap();
        assert!(auto.status.success(), "{directory}/{name}: {auto:?}");

        let typed = omniex()
            .arg("extract")
            .arg("--type")
            .arg(slug)
            .arg(fixture(directory, name))
            .arg("--json")
            .output()
            .unwrap();
        assert!(typed.status.success(), "{directory}/{name}: {typed:?}");
        let value: serde_json::Value = serde_json::from_slice(&typed.stdout).unwrap();
        assert_eq!(value[0]["type"], slug);

        let all = omniex()
            .arg("extract")
            .arg("--all")
            .arg(fixture(directory, name))
            .arg("--json")
            .output()
            .unwrap();
        assert!(all.status.success(), "{directory}/{name}: {all:?}");
        let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
        assert!(
            value
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["type"] == slug)
        );
    }
}

#[test]
fn cli_rejects_wrong_type_and_empty_input() {
    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg("office")
        .arg(fixture("rar5", "archive.rar"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    let empty = omniex()
        .arg("extract")
        .arg("--type")
        .arg("rar5")
        .arg(fixture("rar5", "manifest.toml"))
        .output()
        .unwrap();
    assert!(!empty.status.success());
}

#[test]
fn apple_keychain_extracts_the_database_blob() {
    assert_eq!(
        extracted("apple-keychain", "apple-keychain", "login.keychain"),
        expected_hashes("apple-keychain", "login.hash")
    );
}

#[test]
fn apple_keychain_probe_and_negative_inputs() {
    let extractor = extract::by_slug("apple-keychain").expect("Apple keychain extractor");
    assert!(matches!(
        extractor.probe(&artifact("apple-keychain", "login.keychain")),
        Probe::Yes(reason) if reason.contains("keychain")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a keychain".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("apple-keychain", "login.keychain")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..80].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", data[..300].to_vec()))
            .is_err()
    );
}

#[test]
fn apple_secure_notes_extracts_every_protected_note() {
    assert_eq!(
        extracted(
            "apple-secure-notes",
            "apple-secure-notes",
            "NoteStore.sqlite"
        ),
        expected_hashes("apple-secure-notes", "NoteStore.hash")
    );
}

#[test]
fn apple_secure_notes_probe_and_negative_inputs() {
    let extractor = extract::by_slug("apple-secure-notes").expect("Apple Notes extractor");
    assert!(matches!(
        extractor.probe(&artifact("apple-secure-notes", "NoteStore.sqlite")),
        Probe::Yes(reason) if reason.contains("Notes")
    ));
    assert_eq!(
        extractor.probe(&artifact("apple-secure-notes", "empty.sqlite")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a database".to_vec())),
        Probe::No
    );
    assert!(
        extractor
            .extract(&artifact("apple-secure-notes", "empty.sqlite"))
            .is_err()
    );
    let data = std::fs::read(fixture("apple-secure-notes", "NoteStore.sqlite")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..512].to_vec()))
            .is_err()
    );
}

#[test]
fn macos_shadow_hash_plists_extract() {
    assert_eq!(
        extracted("macos-sha1", "macos-sha1", "user.plist"),
        expected_hashes("macos-sha1", "user.hash")
    );
    assert_eq!(
        extracted("macos-sha512", "macos-sha512", "user.plist"),
        expected_hashes("macos-sha512", "user.hash")
    );
    assert_eq!(
        extracted("macos-pbkdf2-sha512", "macos-pbkdf2-sha512", "user.plist"),
        expected_hashes("macos-pbkdf2-sha512", "user.hash")
    );
}

#[test]
fn macos_shadow_hash_probe_and_negative_inputs() {
    for (slug, directory) in [
        ("macos-sha1", "macos-sha1"),
        ("macos-sha512", "macos-sha512"),
        ("macos-pbkdf2-sha512", "macos-pbkdf2-sha512"),
    ] {
        let extractor = extract::by_slug(slug).expect("macOS extractor");
        assert!(matches!(
            extractor.probe(&artifact(directory, "user.plist")),
            Probe::Yes(reason) if reason.contains("macOS")
        ));
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
            Probe::No
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("text", b"not a plist".to_vec())),
            Probe::No
        );
        let data = std::fs::read(fixture(directory, "user.plist")).unwrap();
        assert!(
            extractor
                .extract(&Artifact::from_bytes("short", data[..32].to_vec()))
                .is_err()
        );
    }

    assert_eq!(
        extract::by_slug("macos-sha1")
            .unwrap()
            .probe(&artifact("macos-sha512", "user.plist")),
        Probe::No
    );
    assert_eq!(
        extract::by_slug("macos-pbkdf2-sha512")
            .unwrap()
            .probe(&artifact("macos-sha512", "user.plist")),
        Probe::No
    );
}

#[test]
fn apple_cli_auto_detects_and_selects_by_type() {
    for (directory, name, slug) in [
        ("apple-keychain", "login.keychain", "apple-keychain"),
        (
            "apple-secure-notes",
            "NoteStore.sqlite",
            "apple-secure-notes",
        ),
        ("macos-sha1", "user.plist", "macos-sha1"),
        ("macos-sha512", "user.plist", "macos-sha512"),
        ("macos-pbkdf2-sha512", "user.plist", "macos-pbkdf2-sha512"),
    ] {
        let auto = omniex()
            .arg("extract")
            .arg(fixture(directory, name))
            .output()
            .unwrap();
        assert!(auto.status.success(), "{directory}/{name}: {auto:?}");

        let typed = omniex()
            .arg("extract")
            .arg("--type")
            .arg(slug)
            .arg(fixture(directory, name))
            .arg("--json")
            .output()
            .unwrap();
        assert!(typed.status.success(), "{directory}/{name}: {typed:?}");
        let value: serde_json::Value = serde_json::from_slice(&typed.stdout).unwrap();
        assert_eq!(value[0]["type"], slug);

        let all = omniex()
            .arg("extract")
            .arg("--all")
            .arg(fixture(directory, name))
            .arg("--json")
            .output()
            .unwrap();
        assert!(all.status.success(), "{directory}/{name}: {all:?}");
        let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
        assert!(
            value
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["type"] == slug)
        );
    }
}

#[test]
fn apple_cli_rejects_wrong_type_and_empty_input() {
    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg("macos-sha1")
        .arg(fixture("macos-sha512", "user.plist"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    let empty = omniex()
        .arg("extract")
        .arg("--type")
        .arg("apple-keychain")
        .arg(fixture("apple-keychain", "manifest.toml"))
        .output()
        .unwrap();
    assert!(!empty.status.success());
}
