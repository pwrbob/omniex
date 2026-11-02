//! LDAP LDIF password attribute extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/ldap")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes(
        "sample.ldif",
        std::fs::read(fixture("sample.ldif")).unwrap(),
    )
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn ldap_extractors_find_their_attributes() {
    for slug in ["ldap-sha1", "ldap-ssha1", "ldap-ssha256", "ldap-ssha512"] {
        let extractor = extract::by_slug(slug).expect("LDAP extractor");
        assert!(
            matches!(extractor.probe(&artifact()), Probe::Yes(_)),
            "{slug}"
        );
        let hashes = extractor.extract(&artifact()).expect("extract");
        assert_eq!(hashes.len(), 1, "{slug}");
        assert_eq!(
            hashes[0].render(&RenderOptions::default()).unwrap(),
            std::fs::read_to_string(fixture(&format!("{slug}.hash")))
                .unwrap()
                .trim_end(),
            "{slug}"
        );
    }
}

#[test]
fn ldap_ldif_is_ambiguous_but_all_emits_every_type() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.ldif"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("ambiguous artifact"));

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg("--json")
        .arg(fixture("sample.ldif"))
        .output()
        .unwrap();
    assert!(all.status.success());
    let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 4);
}

#[test]
fn ldap_extractors_reject_unrelated_files() {
    let text = Artifact::from_bytes("plain", b"userPassword: {CRYPT}abc".to_vec());
    for slug in ["ldap-sha1", "ldap-ssha1", "ldap-ssha256", "ldap-ssha512"] {
        let extractor = extract::by_slug(slug).expect("LDAP extractor");
        assert_eq!(extractor.probe(&text), Probe::No, "{slug}");
        assert!(extractor.extract(&text).is_err(), "{slug}");
    }
}
