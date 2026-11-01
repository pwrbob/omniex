//! Signatureless token extraction with explicit type selection.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};

fn fixture(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join("token.txt")
}

fn artifact(kind: &str) -> Artifact {
    Artifact::from_bytes(kind, std::fs::read(fixture(kind)).expect("read token"))
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn token_extractors_are_possible_but_not_confident() {
    for (slug, kind) in [("fernet", "fernet"), ("jwt", "jwt")] {
        let extractor = extract::by_slug(slug).expect("token extractor");
        assert!(matches!(extractor.probe(&artifact(kind)), Probe::Maybe(_)));
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("text", b"not-a-token".to_vec())),
            Probe::No
        );
    }
}

#[test]
fn token_extractors_round_trip_their_artifacts() {
    for (slug, kind) in [("fernet", "fernet"), ("jwt", "jwt")] {
        let extractor = extract::by_slug(slug).expect("token extractor");
        let hashes = extractor.extract(&artifact(kind)).expect("extract");
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0].render(&omniex::RenderOptions::default()).unwrap(),
            std::fs::read_to_string(fixture(kind)).unwrap().trim_end()
        );
    }
}

#[test]
fn token_files_require_an_explicit_type() {
    for (kind, slug) in [("fernet", "fernet"), ("jwt", "jwt")] {
        let automatic = omniex().arg("extract").arg(fixture(kind)).output().unwrap();
        assert_eq!(automatic.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&automatic.stderr).contains("has no reliable signature"));
        assert!(!automatic.stderr.is_empty());

        let explicit = omniex()
            .args(["extract", "--type", slug])
            .arg(fixture(kind))
            .output()
            .unwrap();
        assert!(explicit.status.success());
        assert_eq!(
            String::from_utf8(explicit.stdout).unwrap().trim_end(),
            std::fs::read_to_string(fixture(kind)).unwrap().trim_end()
        );
    }
}

#[test]
fn all_does_not_promote_token_guesses() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("jwt"))
        .arg("--all")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"));
}

#[test]
fn malformed_tokens_are_reported_without_partial_output() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bad-token.txt");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not-a-token").unwrap();

    let output = omniex()
        .args(["extract", "--type", "jwt"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot extract `jwt`"));
}
