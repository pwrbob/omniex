//! Extraction behavior for registered extractors.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract;
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/gpg")
        .join(name)
}

fn expected(name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(name))
        .expect("read expected fixture")
        .lines()
        .map(str::to_owned)
        .collect()
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

#[test]
fn gpg_extracts_every_secret_key_as_the_same_instance() {
    let extractor = extract::by_slug("gpg").expect("gpg extractor");
    let hashes = extractor
        .extract(&std::fs::read(fixture("testkey1.key")).unwrap())
        .expect("extract testkey1");
    assert_eq!(hashes.len(), 2);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(17010)));
    assert!(!hashes[0].modes().contains(&Mode::Hashcat(17020)));

    let rendered = hashes
        .iter()
        .map(|value| value.render(&RenderOptions::default()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rendered, expected("testkey1.hash"));

    let john = hashes
        .iter()
        .map(|value| {
            value
                .render(&RenderOptions {
                    tool: Tool::John,
                    ..RenderOptions::default()
                })
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(john, expected("testkey1.hash"));
}

#[test]
fn gpg_extracts_elliptic_curve_keys() {
    let output = omniex()
        .args(["extract"])
        .arg(fixture("ec_testkey1.key"))
        .args(["--type", "gpg", "--format", "john"])
        .output()
        .expect("extract runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        expected("ec_testkey1.hash")
    );
}

#[test]
fn gpg_auto_detects_an_artifact() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("ec_testkey1.key"))
        .args(["--format", "john"])
        .output()
        .expect("extract runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        expected("ec_testkey1.hash")
    );
}

#[test]
fn extract_rejects_unknown_types_and_unrecognized_artifacts() {
    let wrong_type = omniex()
        .args(["extract"])
        .arg(fixture("ec_testkey1.key"))
        .args(["--type", "md5"])
        .output()
        .expect("extract runs");
    assert_eq!(wrong_type.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&wrong_type.stderr)
            .contains("no extractor is registered for `md5`")
    );

    let text = scratch("not-a-key.txt");
    std::fs::write(&text, b"not an OpenPGP artifact").unwrap();
    let unrecognized = omniex().arg("extract").arg(&text).output().unwrap();
    let _ = std::fs::remove_file(text);
    assert_eq!(unrecognized.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unrecognized.stderr).contains("no extractor recognized"));
}

#[test]
fn extract_reports_truncated_and_empty_artifacts() {
    let key = std::fs::read(fixture("testkey1.key")).unwrap();
    let empty = scratch("empty.key");
    let truncated = scratch("truncated.key");
    std::fs::write(&empty, b"").unwrap();
    std::fs::write(&truncated, &key[..200]).unwrap();

    for path in [&empty, &truncated] {
        let output = omniex()
            .args(["extract"])
            .arg(path)
            .args(["--type", "gpg"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", path.display());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot extract `gpg`"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = std::fs::remove_file(empty);
    let _ = std::fs::remove_file(truncated);
}
