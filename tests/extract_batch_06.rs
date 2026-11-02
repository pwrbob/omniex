//! 1Password, Bitwarden, and LastPass extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, MemorySource, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn with_members(kind: &str, name: &str, members: &[(&str, &str)]) -> Artifact {
    let mut artifact = artifact(kind, name);
    for (member, file) in members {
        artifact = artifact.with_member(
            *member,
            MemorySource::from(std::fs::read(fixture(kind, file)).unwrap()),
        );
    }
    artifact
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

macro_rules! extractor {
    ($slug:expr) => {
        match extract::by_slug($slug) {
            Some(extractor) => extractor,
            None => return,
        }
    };
}

fn registered(slug: &str) -> bool {
    extract::by_slug(slug).is_some()
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn john(value: &dyn omniex::HashValue) -> String {
    value
        .render(&RenderOptions {
            tool: Tool::John,
            ..RenderOptions::default()
        })
        .unwrap()
}

#[test]
fn onepassword_cloud_extracts_the_hashcat_serialization() {
    let extractor = extractor!("onepassword-cloud");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("onepassword-cloud", "profile.js")),
        Probe::Yes(reason) if reason == "1Password cloudkeychain profile"
    ));
    let hashes = extractor
        .extract(&artifact("onepassword-cloud", "profile.js"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-cloud", "profile.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(8200)));
}

#[test]
fn onepassword_cloud_rejects_bad_profiles() {
    let extractor = extractor!("onepassword-cloud");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("profile.js", b"not json".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty.js", Vec::new())),
        Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "truncated.js",
                br#"{"salt":"AAAA","iterations":40000,"masterKey":"b3BkYXRhMDE="}"#.to_vec()
            ))
            .is_err()
    );
}

#[test]
fn onepassword_cloud_is_ambiguous_with_cloudkeychain() {
    if !registered("onepassword-cloud") {
        return;
    }
    let output = omniex()
        .arg("extract")
        .arg(fixture("onepassword-cloud", "profile.js"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ambiguous artifact"), "{stderr}");
    assert!(stderr.contains("cloudkeychain"), "{stderr}");
    assert!(stderr.contains("onepassword-cloud"), "{stderr}");

    let explicit = omniex()
        .args(["extract", "--type", "onepassword-cloud"])
        .arg(fixture("onepassword-cloud", "profile.js"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8_lossy(&explicit.stdout).trim_end(),
        expected("onepassword-cloud", "profile.hash")
    );
}

#[test]
fn onepassword_mobile_extracts_every_account() {
    let extractor = extractor!("onepassword-mobile");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("onepassword-mobile", "account.json")),
        Probe::Yes(reason) if reason == "1Password mobile keychain accounts"
    ));
    let hashes = extractor
        .extract(&artifact("onepassword-mobile", "account.json"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-mobile", "account.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(31800)));

    let mut document: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture("onepassword-mobile", "account.json")).unwrap(),
    )
    .unwrap();
    let mut second = document["accounts"][0].clone();
    second["email"] = serde_json::Value::String("other@hashcat.net".to_owned());
    document["accounts"].as_array_mut().unwrap().push(second);
    let hashes = extractor
        .extract(&Artifact::from_bytes(
            "accounts.json",
            serde_json::to_vec(&document).unwrap(),
        ))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        hashes[1].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-mobile", "account.hash")
            .replace("31800@hashcat.net", "other@hashcat.net")
    );
}

#[test]
fn onepassword_mobile_rejects_incomplete_records() {
    let extractor = extractor!("onepassword-mobile");
    for data in [
        br#"{"accounts":[]}"#.to_vec(),
        br#"{"accounts":[{"email":"a@b.c"}]}"#.to_vec(),
        br#"{"accounts":[{"email":"a@b.c","hkdf_salt":"00","hkdf_key":"00","iterations":1,"iv":"00","ciphertext":"00","tag":"00"}]}"#.to_vec(),
        b"not json".to_vec(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("bad.json", data)),
            Probe::No
        );
    }
}

#[test]
fn bitwarden_extracts_and_scans_every_account() {
    let extractor = extractor!("bitwarden");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("bitwarden", "data.json")),
        Probe::Yes(reason) if reason == "Bitwarden local account data"
    ));
    let hashes = extractor
        .extract(&artifact("bitwarden", "data.json"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("bitwarden", "data.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23400)));

    let hashes = extractor
        .extract(&artifact("bitwarden", "multi.json"))
        .expect("extract");
    let rendered = hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered, expected("bitwarden", "multi.hash"));
}

#[test]
fn bitwarden_rejects_exports_without_a_master_key_hash() {
    let extractor = extractor!("bitwarden");
    for data in [
        br#"{"encrypted":true,"passwordProtected":true,"kdfType":0,"kdfIterations":100000,"salt":"c2FsdA==","data":"ZGF0YQ=="}"#.to_vec(),
        b"not json".to_vec(),
        Vec::new(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("export.json", data)),
            Probe::No
        );
    }
}

#[test]
fn lastpass_extracts_the_encu_record() {
    let extractor = extractor!("lastpass");
    let artifact = with_members(
        "lastpass",
        "vault.lpb64",
        &[
            ("username", "username.txt"),
            ("iterations", "iterations.txt"),
        ],
    );
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Yes(reason) if reason == "LastPass vault ENCU record"
    ));
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("lastpass", "vault.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(6800)));
}

#[test]
fn lastpass_requires_username_and_iterations() {
    let extractor = extractor!("lastpass");
    let artifact = artifact("lastpass", "vault.lpb64");
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Maybe(reason) if reason.contains("companions")
    ));
    assert!(extractor.extract(&artifact).is_err());

    let output = omniex()
        .args(["extract", "--type", "lastpass"])
        .arg(fixture("lastpass", "vault.lpb64"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing LastPass username"));

    let auto = omniex()
        .arg("extract")
        .arg(fixture("lastpass", "vault.lpb64"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("has no reliable signature"));
}

#[test]
fn lastpass_rejects_broken_vaults() {
    let extractor = extractor!("lastpass");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", b"not a vault".to_vec())),
        Probe::No
    );
    let truncated = b"LPB64".to_vec();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", truncated))
            .is_err()
    );

    let mut blob = b"LPAV".to_vec();
    blob.extend_from_slice(&3u32.to_be_bytes());
    blob.extend_from_slice(b"ENC");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("truncated", blob)),
        Probe::No
    );
}

#[test]
fn lpcli_extracts_the_cli_state() {
    let extractor = extractor!("lpcli");
    let artifact = with_members(
        "lpcli",
        "verify.bin",
        &[
            ("username", "username.txt"),
            ("iterations", "iterations.txt"),
        ],
    );
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Yes(reason) if reason == "LastPass CLI verify file"
    ));
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(john(hashes[0].as_ref()), expected("lpcli", "verify.hash"));
    assert!(hashes[0].modes().contains(&Mode::John("lpcli")));
}

#[test]
fn lpcli_requires_companions_and_a_complete_verify_file() {
    let extractor = extractor!("lpcli");
    let artifact = artifact("lpcli", "verify.bin");
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Maybe(reason) if reason.contains("companions")
    ));
    assert!(extractor.extract(&artifact).is_err());

    assert_eq!(
        extractor.probe(&Artifact::from_bytes("short", vec![0; 63])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );

    let output = omniex()
        .args(["extract", "--type", "lpcli", "--format", "john"])
        .arg(fixture("lpcli", "verify.bin"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing LastPass CLI username"));
}

#[test]
fn signatureless_extractors_need_an_explicit_type() {
    if !registered("lpcli") {
        return;
    }
    let output = omniex()
        .arg("extract")
        .arg(fixture("lpcli", "verify.bin"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"));
}
