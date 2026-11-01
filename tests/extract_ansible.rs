//! Ansible Vault extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, ExtractError, Extracted, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/ansible")
        .join(name)
}

fn artifact(name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(name)).expect("read artifact"))
}

fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(path.parent().expect("scratch directory")).expect("create scratch");
    path
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
fn ansible_probe_requires_the_vault_header() {
    let extractor = extract::by_slug("ansible-vault").expect("ansible extractor");
    assert!(matches!(
        extractor.probe(&artifact("sample.yml")),
        Probe::Yes(reason) if reason == "Ansible Vault header"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a vault".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn ansible_extracts_the_vault_instance() {
    let extractor = extract::by_slug("ansible-vault").expect("ansible extractor");
    let hashes = extractor.extract(&artifact("sample.yml")).expect("extract");
    assert_eq!(hashes.len(), 1);
    let expected = std::fs::read_to_string(fixture("sample.hash")).unwrap();
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected.trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(16900)));
    assert!(hashes[0].modes().contains(&Mode::John("ansible")));
}

#[test]
fn ansible_extracts_through_the_cli_and_auto_detection() {
    for args in [
        vec!["extract", "--type", "ansible-vault"],
        vec!["extract"],
        vec!["extract", "--all"],
    ] {
        let output = omniex()
            .args(args)
            .arg(fixture("sample.yml"))
            .output()
            .expect("extract runs");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim_end(),
            std::fs::read_to_string(fixture("sample.hash"))
                .unwrap()
                .trim_end()
        );
    }
}

#[test]
fn ansible_extract_json_reports_the_type() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("sample.yml"))
        .args(["--all", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = value.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["type"], "ansible-vault");
}

#[test]
fn ansible_rejects_unsupported_ciphers_and_malformed_bodies() {
    let extractor = extract::by_slug("ansible-vault").expect("ansible extractor");
    let valid = std::fs::read_to_string(fixture("sample.yml")).unwrap();

    let unsupported = valid.replacen("AES256", "AES128", 1);
    let error = extract_error(extractor.extract(&Artifact::from_bytes(
        "unsupported",
        unsupported.into_bytes(),
    )));
    assert!(
        error
            .to_string()
            .contains("unsupported Ansible Vault cipher")
    );

    let bad_hex = valid.replacen(
        "$ANSIBLE_VAULT;1.1;AES256\n",
        "$ANSIBLE_VAULT;1.1;AES256\nzz",
        1,
    );
    let error =
        extract_error(extractor.extract(&Artifact::from_bytes("bad-hex", bad_hex.into_bytes())));
    assert!(error.to_string().contains("invalid Ansible Vault body"));

    let short = "$ANSIBLE_VAULT;1.1;AES256\n00\n";
    let error =
        extract_error(extractor.extract(&Artifact::from_bytes("short", short.as_bytes().to_vec())));
    assert!(error.to_string().contains("must contain salt"));

    let empty = "$ANSIBLE_VAULT;1.1;AES256\n";
    let error = extract_error(extractor.extract(&Artifact::from_bytes(
        "empty-body",
        empty.as_bytes().to_vec(),
    )));
    assert!(error.to_string().contains("body is empty"));
}

#[test]
fn ansible_reports_malformed_cli_input_without_partial_output() {
    let path = scratch("malformed-vault.yml");
    let valid = std::fs::read_to_string(fixture("sample.yml")).unwrap();
    std::fs::write(&path, valid.replacen("AES256", "AES128", 1)).unwrap();

    let output = omniex()
        .arg("extract")
        .arg(&path)
        .args(["--all"])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot extract `ansible-vault`"));
}
