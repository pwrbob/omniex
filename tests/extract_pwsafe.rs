//! Password Safe v3 extraction into hashcat and John types.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/pwsafe-v3")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes(
        "sample.psafe3",
        std::fs::read(fixture("sample.psafe3")).expect("read database"),
    )
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pwsafe_probes_require_the_magic_and_enough_header() {
    for slug in ["pwsafe", "pwsafe-v3"] {
        let extractor = extract::by_slug(slug).expect("pwsafe extractor");
        assert!(matches!(extractor.probe(&artifact()), Probe::Yes(_)));
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("bad", b"NOPE".to_vec())),
            Probe::No
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("short", b"PWS3".to_vec())),
            Probe::No
        );
    }
}

#[test]
fn pwsafe_extracts_both_serializations() {
    let v3 = extract::by_slug("pwsafe-v3").expect("pwsafe-v3 extractor");
    let hashes = v3.extract(&artifact()).expect("extract hashcat");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&omniex::RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("sample.v3.hash"))
            .unwrap()
            .trim_end()
    );

    let john = extract::by_slug("pwsafe").expect("pwsafe extractor");
    let hashes = john.extract(&artifact()).expect("extract John");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&omniex::RenderOptions {
                tool: omniex::Tool::John,
                ..omniex::RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("sample.john.hash"))
            .unwrap()
            .trim_end()
    );
}

#[test]
fn pwsafe_is_ambiguous_without_type_and_cannot_share_one_format() {
    let automatic = omniex()
        .arg("extract")
        .arg(fixture("sample.psafe3"))
        .output()
        .unwrap();
    assert_eq!(automatic.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&automatic.stderr);
    assert!(stderr.contains("ambiguous artifact"), "{stderr}");
    assert!(stderr.contains("pwsafe"), "{stderr}");
    assert!(stderr.contains("pwsafe-v3"), "{stderr}");

    for format in ["hashcat", "john"] {
        let all = omniex()
            .arg("extract")
            .arg("--all")
            .args(["--format", "json"])
            .args(["--tool", format])
            .arg(fixture("sample.psafe3"))
            .output()
            .unwrap();
        assert_eq!(all.status.code(), Some(1));
        assert!(all.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&all.stderr).contains("cannot render extracted"),
            "{}",
            String::from_utf8_lossy(&all.stderr)
        );
    }
}

#[test]
fn pwsafe_rejects_truncated_headers() {
    let data = std::fs::read(fixture("sample.psafe3")).unwrap();
    let truncated = Artifact::from_bytes("truncated.psafe3", data[..100].to_vec());
    for slug in ["pwsafe", "pwsafe-v3"] {
        let extractor = extract::by_slug(slug).expect("pwsafe extractor");
        assert!(extractor.extract(&truncated).is_err());
    }
}
