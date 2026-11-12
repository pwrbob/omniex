//! Unix password-file extraction for common crypt schemes.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

const SLUGS: &[&str] = &[
    "descrypt",
    "md5crypt",
    "apr1",
    "sha256crypt",
    "sha512crypt",
    "yescrypt",
    "bcrypt",
    "bsdi-crypt",
    "sunmd5",
    "sha1crypt",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/shadow")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("shadow", std::fs::read(fixture("shadow")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn shadow_extractors_select_their_hash_scheme() {
    for slug in SLUGS {
        let extractor = extract::by_slug(slug).expect("shadow extractor");
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
fn shadow_file_is_ambiguous_and_all_emits_every_scheme() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("shadow"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("ambiguous artifact"));

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .args(["--format", "json"])
        .arg(fixture("shadow"))
        .output()
        .unwrap();
    assert!(all.status.success());
    let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), SLUGS.len());
}

#[test]
fn shadow_extractors_ignore_locked_and_unrelated_entries() {
    let input = Artifact::from_bytes("shadow", b"root:*:1:0:99999:7:::\nuser:!:$1$bad\n".to_vec());
    for slug in SLUGS {
        let extractor = extract::by_slug(slug).expect("shadow extractor");
        assert!(extractor.extract(&input).is_err(), "{slug}");
    }
}
