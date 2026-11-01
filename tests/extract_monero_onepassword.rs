//! Monero key-file and 1Password agilekeychain extraction.

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

#[test]
fn agile_onepassword_probes_require_a_key_list() {
    for slug in ["agilekeychain", "onepassword-agile"] {
        let extractor = extract::by_slug(slug).expect("1Password extractor");
        assert!(matches!(
            extractor.probe(&artifact("onepassword-agile", "encryptionKeys.js")),
            Probe::Yes(reason) if reason == "1Password agilekeychain key list"
        ));
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("bad.json", b"{\"list\":[]}".to_vec())),
            Probe::No
        );
    }
}

#[test]
fn agile_onepassword_extracts_both_serializations() {
    let john = extract::by_slug("agilekeychain").expect("agile extractor");
    let hashes = john
        .extract(&artifact("onepassword-agile", "encryptionKeys.js"))
        .expect("extract John");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("onepassword-agile", "agile.hash"))
            .unwrap()
            .trim_end()
    );

    let hashcat = extract::by_slug("onepassword-agile").expect("hashcat extractor");
    let hashes = hashcat
        .extract(&artifact("onepassword-agile", "encryptionKeys.js"))
        .expect("extract hashcat");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        hashes
            .iter()
            .map(|value| value.render(&RenderOptions::default()).unwrap())
            .collect::<Vec<_>>(),
        std::fs::read_to_string(fixture("onepassword-agile", "onepassword.hash"))
            .unwrap()
            .lines()
            .collect::<Vec<_>>()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(6600)));
}

#[test]
fn agile_onepassword_is_ambiguous_and_requires_type() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("onepassword-agile", "encryptionKeys.js"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&auto.stderr);
    assert!(stderr.contains("ambiguous artifact"), "{stderr}");
    assert!(stderr.contains("agilekeychain"), "{stderr}");
    assert!(stderr.contains("onepassword-agile"), "{stderr}");

    for (slug, format, expected) in [
        ("agilekeychain", "john", "agile.hash"),
        ("onepassword-agile", "hashcat", "onepassword.hash"),
    ] {
        let output = omniex()
            .args(["extract", "--type", slug, "--format", format])
            .arg(fixture("onepassword-agile", "encryptionKeys.js"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim_end(),
            std::fs::read_to_string(fixture("onepassword-agile", expected))
                .unwrap()
                .trim_end()
        );
    }
}

#[test]
fn agile_onepassword_rejects_malformed_key_data() {
    let extractor = extract::by_slug("agilekeychain").expect("agile extractor");
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "missing",
                b"{\"list\":[{\"data\":\"!!!\"}]}".to_vec()
            ))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("text", b"not json".to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", b"{\"list\":[]}".to_vec()))
            .is_err()
    );
}

#[test]
fn monero_probe_uses_the_key_file_extension() {
    let extractor = extract::by_slug("monero").expect("Monero extractor");
    assert!(!extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("monero", "wallet.keys")),
        Probe::Maybe(reason) if reason.contains("extension")
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("wallet.bin", vec![1, 2, 3])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty.keys", Vec::new())),
        Probe::No
    );
}

#[test]
fn monero_extracts_the_key_file_for_john() {
    let extractor = extract::by_slug("monero").expect("Monero extractor");
    let hashes = extractor
        .extract(&artifact("monero", "wallet.keys"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("monero", "wallet.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("Monero")));
}

#[test]
fn monero_requires_an_explicit_type() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("monero", "wallet.keys"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("has no reliable signature"));

    let explicit = omniex()
        .args(["extract", "--type", "monero", "--format", "john"])
        .arg(fixture("monero", "wallet.keys"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
}
