//! MultiBit, BitShares, and ADXCSOUF extraction.

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
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn multibit_probes_distinguish_key_and_hd_files() {
    let key = extract::by_slug("multibit").expect("MultiBit key extractor");
    assert!(matches!(
        key.probe(&artifact("multibit", "classic.key")),
        Probe::Yes(reason) if reason == "MultiBit Classic key file"
    ));
    let hd = extract::by_slug("multibit-hd").expect("MultiBit HD extractor");
    assert!(matches!(
        hd.probe(&artifact("multibit", "wallet.wallet.aes")),
        Probe::Maybe(reason) if reason.contains("extension")
    ));
    assert!(!hd.exact());
}

#[test]
fn multibit_extracts_classic_and_hd_serializations() {
    let key = extract::by_slug("multibit").expect("MultiBit key extractor");
    let hashes = key
        .extract(&artifact("multibit", "classic.key"))
        .expect("extract classic");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("multibit", "classic.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(22500)));

    let hd = extract::by_slug("multibit-hd").expect("MultiBit HD extractor");
    let hashes = hd
        .extract(&artifact("multibit", "wallet.wallet.aes"))
        .expect("extract HD");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("multibit", "wallet.hash"))
            .unwrap()
            .trim_end()
    );
}

#[test]
fn bitshares_backup_requires_explicit_type_and_round_trips() {
    let extractor = extract::by_slug("bitshares-payload").expect("BitShares extractor");
    assert!(!extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("bitshares", "wallet.bin")),
        Probe::Maybe(reason) if reason.contains("extension")
    ));
    let hashes = extractor
        .extract(&artifact("bitshares", "wallet.bin"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("bitshares", "wallet.hash"))
            .unwrap()
            .trim_end()
    );

    let auto = omniex()
        .arg("extract")
        .arg(fixture("bitshares", "wallet.bin"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
}

#[test]
fn adxcrypt_extracts_all_user_records() {
    let extractor = extract::by_slug("adxcrypt").expect("ADX extractor");
    assert!(!extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("adxcrypt", "ADXCSOUF.DAT")),
        Probe::Maybe(reason) if reason.contains("ADXCSOUF")
    ));
    let hashes = extractor
        .extract(&artifact("adxcrypt", "ADXCSOUF.DAT"))
        .expect("extract");
    assert_eq!(
        hashes
            .iter()
            .map(|value| {
                value
                    .render(&RenderOptions {
                        tool: Tool::John,
                        ..RenderOptions::default()
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>(),
        std::fs::read_to_string(fixture("adxcrypt", "ADXCSOUF.hash"))
            .unwrap()
            .lines()
            .collect::<Vec<_>>()
    );
}

#[test]
fn adxcrypt_needs_an_explicit_type_and_rejects_unrelated_text() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("adxcrypt", "ADXCSOUF.DAT"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("has no reliable signature"));

    let typed = omniex()
        .arg("extract")
        .arg(fixture("adxcrypt", "ADXCSOUF.DAT"))
        .args(["--type", "adxcrypt", "--tool", "john"])
        .output()
        .unwrap();
    assert!(typed.status.success());

    let extractor = extract::by_slug("adxcrypt").expect("ADX extractor");
    assert!(
        extractor
            .extract(&Artifact::from_bytes("plain", b"hello world".to_vec()))
            .is_err()
    );
}
