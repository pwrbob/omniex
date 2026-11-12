//! Dashlane and BKS extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
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

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
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
fn dashlane_probe_distinguishes_archives_from_extensions() {
    let extractor = extract::by_slug("dashlane").expect("Dashlane extractor");
    assert!(matches!(
        extractor.probe(&artifact("dashlane", "sample.dash")),
        Probe::Yes(reason) if reason == "Dashlane secure archive"
    ));
    assert!(matches!(
        extractor.probe(&artifact("dashlane", "sample.aes")),
        Probe::Maybe(reason) if reason.contains("extension")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("data.bin", vec![0; 256])),
        Probe::No
    );
}

#[test]
fn dashlane_extracts_aes_and_secure_archives() {
    let extractor = extract::by_slug("dashlane").expect("Dashlane extractor");
    for (file, expected) in [
        ("sample.aes", "sample.aes.hash"),
        ("sample.dash", "sample.dash.hash"),
    ] {
        let hashes = extractor
            .extract(&artifact("dashlane", file))
            .expect("extract");
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            john(hashes[0].as_ref()),
            std::fs::read_to_string(fixture("dashlane", expected))
                .unwrap()
                .trim_end()
        );
        assert!(hashes[0].modes().contains(&Mode::John("dashlane")));
    }
}

#[test]
fn dashlane_secure_archive_auto_detects_but_aes_requires_type() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("dashlane", "sample.dash"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let aes = omniex()
        .arg("extract")
        .arg(fixture("dashlane", "sample.aes"))
        .output()
        .unwrap();
    assert_eq!(aes.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&aes.stderr).contains("has no reliable signature"));

    let explicit = omniex()
        .args(["extract", "--type", "dashlane", "--tool", "john"])
        .arg(fixture("dashlane", "sample.aes"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
}

#[test]
fn dashlane_rejects_short_and_incomplete_data() {
    let extractor = extract::by_slug("dashlane").expect("Dashlane extractor");
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short.aes", vec![0; 31]))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "broken.dash",
                b"Data BEGIN\n!!!\nData END\n".to_vec()
            ))
            .is_err()
    );
}

#[test]
fn bks_probe_requires_a_complete_keystore() {
    let extractor = extract::by_slug("bks").expect("BKS extractor");
    for version in [1, 2] {
        assert!(matches!(
            extractor.probe(&artifact("bks", &format!("empty-v{version}.bks"))),
            Probe::Yes(reason) if reason == "BKS keystore structure"
        ));
    }
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", vec![0, 0, 0, 9])),
        Probe::No
    );
}

#[test]
fn bks_extracts_both_versions() {
    let extractor = extract::by_slug("bks").expect("BKS extractor");
    for version in [1, 2] {
        let hashes = extractor
            .extract(&artifact("bks", &format!("empty-v{version}.bks")))
            .expect("extract");
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            john(hashes[0].as_ref()),
            std::fs::read_to_string(fixture("bks", &format!("empty-v{version}.hash")))
                .unwrap()
                .trim_end()
        );
        assert!(hashes[0].modes().contains(&Mode::John("BKS")));
    }
}

#[test]
fn bks_auto_detects_and_rejects_truncation() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("bks", "empty-v2.bks"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let extractor = extract::by_slug("bks").expect("BKS extractor");
    let data = std::fs::read(fixture("bks", "empty-v2.bks")).unwrap();
    for len in [4, 8, data.len() - 1] {
        assert!(
            extractor
                .extract(&Artifact::from_bytes("truncated", data[..len].to_vec()))
                .is_err()
        );
    }
}
