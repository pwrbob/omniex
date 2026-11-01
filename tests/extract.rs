//! Extraction behavior and extractor selection.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::types::Gpg;
use omniex::{Mode, Parse, ParseOptions, Render, RenderOptions, Tool};

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

fn artifact(name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(name)).expect("read artifact"))
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
fn artifact_file_source_reads_ranges_without_loading_everything() {
    let path = scratch("range-source.bin");
    std::fs::write(&path, (0..=9).collect::<Vec<u8>>()).unwrap();
    let artifact = Artifact::from_file(&path).expect("open artifact");
    let source = artifact.primary();

    let mut out = [0; 4];
    assert_eq!(source.len(), 10);
    assert_eq!(source.read_at(4, &mut out).unwrap(), 4);
    assert_eq!(out, [4, 5, 6, 7]);
    assert_eq!(source.read_at(8, &mut out).unwrap(), 2);
    assert_eq!(&out[..2], [8, 9]);
    assert_eq!(source.read_at(10, &mut out).unwrap(), 0);

    let _ = std::fs::remove_file(path);
}

#[test]
fn gpg_probe_separates_signatures_from_guesses() {
    let extractor = extract::by_slug("gpg").expect("gpg extractor");

    assert!(matches!(
        extractor.probe(&artifact("testkey1.key")),
        Probe::Yes(reason) if reason == "OpenPGP armor header"
    ));
    assert!(matches!(
        extractor.probe(&Artifact::from_bytes("secret", vec![0xc5])),
        Probe::Yes(reason) if reason == "OpenPGP secret-key packet header"
    ));
    assert!(matches!(
        extractor.probe(&Artifact::from_bytes("public", vec![0xc6])),
        Probe::Maybe(reason) if reason.contains("tag 6")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a key".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn gpg_extracts_every_secret_key_as_the_same_instance() {
    let extractor = extract::by_slug("gpg").expect("gpg extractor");
    let hashes = extractor
        .extract(&artifact("testkey1.key"))
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

    let extractor = extract::by_slug("gpg").expect("gpg extractor");
    let hashes = extractor.extract(&artifact("ec_testkey1.key")).unwrap();
    assert!(hashes.iter().all(|value| {
        value.modes().contains(&Mode::John("gpg"))
            && !value
                .modes()
                .iter()
                .any(|mode| matches!(mode, Mode::Hashcat(_)))
    }));
}

#[test]
fn gpg_auto_detects_an_armored_artifact() {
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
fn extract_all_matches_unique_detection() {
    let automatic = omniex()
        .arg("extract")
        .arg(fixture("testkey1.key"))
        .output()
        .unwrap();
    let explicit_all = omniex()
        .arg("extract")
        .arg(fixture("testkey1.key"))
        .arg("--all")
        .output()
        .unwrap();

    assert!(automatic.status.success());
    assert!(explicit_all.status.success());
    assert_eq!(automatic.stdout, explicit_all.stdout);
}

#[test]
fn extract_all_conflicts_with_type() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("testkey1.key"))
        .args(["--all", "--type", "gpg"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[test]
fn extract_json_reports_type_and_hash() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("testkey1.key"))
        .args(["--all", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = value.as_array().expect("array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["type"], "gpg");
    assert_eq!(entries[0]["hash"], expected("testkey1.hash")[0].as_str());
    assert_eq!(entries[1]["type"], "gpg");
}

#[test]
fn extract_all_does_not_promote_unconfirmed_matches() {
    let public = scratch("all-public-key.packet");
    std::fs::write(&public, [0xc6]).unwrap();
    let output = omniex()
        .arg("extract")
        .arg(&public)
        .arg("--all")
        .output()
        .unwrap();
    let _ = std::fs::remove_file(public);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn auto_detection_does_not_select_signatureless_matches() {
    let public = scratch("public-key.packet");
    std::fs::write(&public, [0xc6]).unwrap();
    let output = omniex().arg("extract").arg(&public).output().unwrap();
    let _ = std::fs::remove_file(public);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("has no reliable signature"), "{stderr}");
    assert!(stderr.contains("gpg (OpenPGP packet tag 6"), "{stderr}");
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
fn explicit_type_skips_probe_selection() {
    let text = scratch("explicit-not-a-key.txt");
    std::fs::write(&text, b"not an OpenPGP artifact").unwrap();
    let output = omniex()
        .arg("extract")
        .arg(&text)
        .args(["--type", "gpg"])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(text);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot extract `gpg`"), "{stderr}");
    assert!(!stderr.contains("no extractor recognized"), "{stderr}");
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

#[test]
fn pgp2hc_encrypted_private_key_fields() {
    let extractor = extract::by_slug("gpg").expect("gpg extractor");
    let hashes = extractor
        .extract(&artifact("gnupg-v1.asc"))
        .expect("extract gnupg v1 key");
    assert_eq!(hashes.len(), 2);
    let hash = hashes[0]
        .as_ref()
        .render(&RenderOptions::default())
        .expect("hashcat render");
    let parsed = Gpg::parse(&hash, &ParseOptions::default()).expect("parse rendered hash");

    assert_eq!(parsed.algorithm, 1);
    assert_eq!(
        parsed.iv,
        [
            0x22, 0x71, 0xf7, 0x18, 0xaf, 0x70, 0xd3, 0xbd, 0x9d, 0x60, 0xc2, 0xae, 0xd9, 0x46,
            0x9b, 0x67
        ]
    );
    assert_eq!(
        parsed.salt,
        [0xcb, 0x18, 0xe7, 0x78, 0x84, 0xf2, 0xf0, 0x55]
    );
    assert_eq!(parsed.s2k_type, 3);
    assert_eq!(parsed.s2k_mode, 254);
    assert_eq!(parsed.s2k_hash, 8);
    assert_eq!(parsed.cipher, 7);
    assert_eq!(parsed.iterations, 65536);
    assert_eq!(parsed.encrypted_size as usize, parsed.encrypted_data.len());
    assert_eq!(parsed.iv_size as usize, parsed.iv.len());
}

#[test]
fn pgp2hc_secret_key_hash_vectors_round_trip() {
    let data = std::fs::read_to_string(fixture("pgp2hc-secret-key-hashes.txt")).unwrap();
    let opts = ParseOptions::default();
    let render = RenderOptions {
        tool: Tool::John,
        ..RenderOptions::default()
    };

    for line in data.lines().filter(|line| !line.is_empty()) {
        let parsed = Gpg::parse(line, &opts).unwrap_or_else(|error| {
            panic!("failed to parse pgp2hc vector {line}: {error}");
        });
        assert_eq!(
            parsed.render(&render).unwrap(),
            line,
            "pgp2hc vector did not round-trip"
        );
    }
}
