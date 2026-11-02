//! Extraction tests for Terra, WIF, Bitcoin Core, MultiBit Classic, BitShares.

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::{HashType, HashValue, RenderOptions};

pub mod types {
    pub use omniex::types::*;
}

pub mod format {
    pub use omniex::format::*;
}

#[path = "../src/extract/bitcoin_wallet.rs"]
mod bitcoin_wallet;
#[path = "../src/extract/bitcoin_wif.rs"]
mod bitcoin_wif;
#[path = "../src/extract/bitshares_wallet.rs"]
mod bitshares_wallet;
#[path = "../src/extract/multibit_wallet.rs"]
mod multibit_wallet;
#[path = "../src/extract/terra.rs"]
mod terra;

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn rendered(result: Result<Extracted, ExtractError>) -> Vec<String> {
    result
        .unwrap()
        .iter()
        .map(|value| value.render(&RenderOptions::default()).unwrap())
        .collect()
}

#[test]
fn terra_recognizes_and_extracts_its_wallet() {
    let extractor = terra::TerraExtractor;
    assert_eq!(extractor.slug(), "terra");
    assert!(matches!(
        extractor.probe(&artifact("terra", "wallet.json")),
        Probe::Yes(reason) if reason.contains("Terra")
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("terra", "wallet.json"))),
        vec![expected("terra", "wallet.hash")]
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a wallet".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn terra_rejects_bad_ciphertext_and_short_messages() {
    let extractor = terra::TerraExtractor;
    let bad = br#"{"name":"x","encrypted_key":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffAAAA"}"#;
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad.json", bad.to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", b"0011".to_vec()))
            .is_err()
    );
    let data = std::fs::read(fixture("terra", "wallet.json")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "truncated",
                data[..data.len() / 2].to_vec()
            ))
            .is_err()
    );
}

#[test]
fn multibit_wallet_recognizes_the_protobuf_wallet() {
    let extractor = multibit_wallet::MultibitWalletExtractor;
    assert_eq!(extractor.slug(), "multibit-wallet");
    assert!(matches!(
        extractor.probe(&artifact("multibit-wallet", "wallet.wallet")),
        Probe::Yes(_)
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("multibit-wallet", "wallet.wallet"))),
        vec![expected("multibit-wallet", "wallet.hash")]
    );
    assert_eq!(
        extractor.probe(&artifact("terra", "wallet.json")),
        Probe::No
    );
    let data = std::fs::read(fixture("multibit-wallet", "wallet.wallet")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "short",
                data[..data.len() / 2].to_vec()
            ))
            .is_err()
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn bitcoin_wallet_recognizes_the_mkey_record() {
    let extractor = bitcoin_wallet::BitcoinWalletExtractor;
    assert_eq!(extractor.slug(), "bitcoin-wallet");
    assert!(matches!(
        extractor.probe(&artifact("bitcoin-wallet", "wallet.dat")),
        Probe::Yes(reason) if reason.contains("mkey")
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("bitcoin-wallet", "wallet.dat"))),
        vec![expected("bitcoin-wallet", "wallet.hash")]
    );
    let data = std::fs::read(fixture("bitcoin-wallet", "wallet.dat")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", data[..20].to_vec()))
            .is_err()
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a wallet".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn bitcoin_wif_derives_the_matching_address() {
    let extractor = bitcoin_wif::BitcoinWifExtractor;
    assert_eq!(extractor.slug(), "bitcoin-wif");
    assert!(matches!(
        extractor.probe(&artifact("bitcoin-wif", "key.txt")),
        Probe::Yes(_)
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("bitcoin-wif", "key.txt"))),
        vec![expected("bitcoin-wif", "key.hash")]
    );
    assert_eq!(
        rendered(extractor.extract(&artifact("bitcoin-wif", "two.txt"))),
        expected("bitcoin-wif", "two.hash")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a key".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "truncated",
            b"KxhashcatxhXkULNJYF8Fu46G28SJrC7x2qwFtRuf38kVjkWxHg".to_vec()
        )),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn bitshares_wallet_extracts_sqlite_and_leveldb_records() {
    let extractor = bitshares_wallet::BitsharesWalletExtractor;
    assert_eq!(extractor.slug(), "bitshares");
    assert!(matches!(
        extractor.probe(&artifact("bitshares", "wallet.sqlite")),
        Probe::Yes(reason) if reason.contains("SQLite")
    ));
    assert!(matches!(
        extractor.probe(&artifact("bitshares", "wallet.ldb")),
        Probe::Yes(reason) if reason.contains("LevelDB")
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("bitshares", "wallet.sqlite"))),
        vec![expected("bitshares", "sqlite.hash")]
    );
    assert_eq!(
        rendered(extractor.extract(&artifact("bitshares", "wallet.ldb"))),
        vec![expected("bitshares", "leveldb.hash")]
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a database".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn bitshares_wallet_scans_every_record() {
    let first = "aa".repeat(64);
    let second = "bb".repeat(64);
    let mut data = b"SQLite format 3\0".to_vec();
    data.extend_from_slice(
        format!("{{\"encryption_key\":\"{first}\"}} garbage {{\"encryption_key\": \"{second}\"}}")
            .as_bytes(),
    );
    let values = rendered(
        bitshares_wallet::BitsharesWalletExtractor.extract(&Artifact::from_bytes("db", data)),
    );
    assert_eq!(values, vec![first, second]);
}

#[test]
fn bitshares_wallet_marks_a_keyless_sqlite_file_as_maybe() {
    let mut data = b"SQLite format 3\0".to_vec();
    data.extend_from_slice(b"no wallet records here");
    let probe = bitshares_wallet::BitsharesWalletExtractor.probe(&Artifact::from_bytes("db", data));
    assert!(matches!(probe, Probe::Maybe(reason) if reason.contains("SQLite")));
}

#[test]
fn extractors_do_not_claim_unrelated_artifacts() {
    let plain = Artifact::from_bytes("plain", b"plain text with no wallet".to_vec());
    for extractor in [
        &terra::TerraExtractor as &dyn Extractor,
        &bitcoin_wif::BitcoinWifExtractor,
        &bitcoin_wallet::BitcoinWalletExtractor,
        &multibit_wallet::MultibitWalletExtractor,
        &bitshares_wallet::BitsharesWalletExtractor,
    ] {
        assert_eq!(extractor.probe(&plain), Probe::No, "{}", extractor.slug());
    }
}

#[test]
fn fixtures_render_for_both_tools_where_applicable() {
    let wif = bitcoin_wif::BitcoinWifExtractor
        .extract(&artifact("bitcoin-wif", "key.txt"))
        .unwrap();
    assert_eq!(
        wif[0].render(&RenderOptions::default()).unwrap(),
        expected("bitcoin-wif", "key.hash")
    );

    for value in bitcoin_wallet::BitcoinWalletExtractor
        .extract(&artifact("bitcoin-wallet", "wallet.dat"))
        .unwrap()
    {
        assert!(
            value
                .modes()
                .iter()
                .any(|mode| matches!(mode, omniex::Mode::Hashcat(11300)))
        );
    }
}
