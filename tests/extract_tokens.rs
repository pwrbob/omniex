//! Fernet and JWT extraction with structural confidence checks.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use omniex::Parse;
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

fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(path.parent().expect("scratch directory")).expect("create scratch");
    path
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn jwt(header: serde_json::Value, signature: &[u8]) -> String {
    let encode = |value: &serde_json::Value| {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serialize JWT header"))
    };
    format!(
        "{}.{}.{}",
        encode(&header),
        encode(&serde_json::json!({"sub": "1"})),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

#[test]
fn structurally_valid_tokens_are_confident() {
    for (slug, kind, reason) in [
        ("fernet", "fernet", "Fernet token structure"),
        (
            "jwt",
            "jwt",
            "JWT HMAC header, payload, and signature structure",
        ),
    ] {
        let extractor = extract::by_slug(slug).expect("token extractor");
        assert!(matches!(
            extractor.probe(&artifact(kind)),
            Probe::Yes(actual) if actual == reason
        ));
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
fn confident_token_files_auto_detect() {
    for (kind, slug) in [("fernet", "fernet"), ("jwt", "jwt")] {
        let automatic = omniex().arg("extract").arg(fixture(kind)).output().unwrap();
        assert!(automatic.status.success());
        assert_eq!(
            String::from_utf8(automatic.stdout).unwrap().trim_end(),
            std::fs::read_to_string(fixture(kind)).unwrap().trim_end()
        );

        let explicit = omniex()
            .args(["extract", "--type", slug])
            .arg(fixture(kind))
            .output()
            .unwrap();
        assert!(explicit.status.success());
    }
}

#[test]
fn non_hmac_jwt_is_possible_but_unconfirmed() {
    let token = jwt(serde_json::json!({"alg": "RS256", "typ": "JWT"}), &[0; 64]);
    let path = scratch("rs256.jwt");
    std::fs::write(&path, &token).unwrap();

    let extractor = extract::by_slug("jwt").expect("jwt extractor");
    assert!(matches!(
        extractor.probe(&Artifact::from_bytes("rs256.jwt", token.clone().into_bytes())),
        Probe::Maybe(reason) if reason.contains("RS256")
    ));

    let automatic = omniex().arg("extract").arg(&path).output().unwrap();
    assert_eq!(automatic.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&automatic.stderr).contains("has no reliable signature"),
        "{}",
        String::from_utf8_lossy(&automatic.stderr)
    );

    let explicit = omniex()
        .args(["extract", "--type", "jwt"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8(explicit.stdout).unwrap().trim_end(),
        token
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn malformed_tokens_are_reported_without_partial_output() {
    let path = scratch("bad-token.txt");
    std::fs::write(&path, b"not-a-token").unwrap();

    for slug in ["fernet", "jwt"] {
        let output = omniex()
            .args(["extract", "--type", slug])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("cannot extract `{slug}`"))
        );
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn malformed_fernet_structure_is_not_a_candidate() {
    let extractor = extract::by_slug("fernet").expect("fernet extractor");
    let wrong_version =
        URL_SAFE_NO_PAD.encode([0x81].into_iter().chain([0; 88]).collect::<Vec<_>>());
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "bad.fernet",
            wrong_version.into_bytes()
        )),
        Probe::No
    );
    assert!(
        omniex::types::Fernet::parse(
            &URL_SAFE_NO_PAD.encode([0x81].into_iter().chain([0; 88]).collect::<Vec<_>>()),
            &omniex::ParseOptions::default()
        )
        .is_err()
    );
}
