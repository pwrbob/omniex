//! Extraction tests for Terra, WIF, Bitcoin Core, MultiBit Classic, BitShares.

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::{HashType, HashValue, RenderOptions, Tool};

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

pub mod extract {
    pub use omniex::extract::*;
}

#[path = "../src/extract/iscsi_chap.rs"]
mod iscsi_chap;
#[path = "../src/extract/radius.rs"]
mod radius;
#[path = "../src/extract/sip_digest.rs"]
mod sip_digest;
#[path = "../src/extract/snmpv3.rs"]
mod snmpv3;
#[path = "../src/extract/tacacs_plus.rs"]
mod tacacs_plus;

fn with_member(kind: &str, name: &str, member: &str, value: Vec<u8>) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
        .with_member(member, omniex::extract::MemorySource::from(value))
}

fn lines(kind: &str, name: &str) -> Vec<String> {
    expected(kind, name).lines().map(str::to_owned).collect()
}

fn rendered_john(result: Result<Extracted, ExtractError>) -> Vec<String> {
    let options = RenderOptions {
        tool: Tool::John,
        ..RenderOptions::default()
    };
    result
        .unwrap()
        .iter()
        .map(|value| value.render(&options).unwrap())
        .collect()
}

fn truncated(kind: &str, name: &str) -> Artifact {
    let data = std::fs::read(fixture(kind, name)).unwrap();
    Artifact::from_bytes("truncated", data[..data.len() / 2].to_vec())
}

#[test]
fn iscsi_chap_recognizes_login_exchanges() {
    let extractor = iscsi_chap::IscsiChapExtractor;
    assert_eq!(extractor.slug(), "iscsi-chap");
    for name in ["login.pcap", "login.pcapng"] {
        assert!(
            matches!(
                extractor.probe(&artifact("iscsi-chap", name)),
                Probe::Yes(reason) if reason.contains("iSCSI")
            ),
            "{name}"
        );
        assert_eq!(
            rendered(extractor.extract(&artifact("iscsi-chap", name))),
            vec![expected("iscsi-chap", "login.hash")],
            "{name}"
        );
    }
    assert_eq!(
        rendered(extractor.extract(&artifact("iscsi-chap", "multi.pcap"))),
        lines("iscsi-chap", "multi.hash")
    );
}

#[test]
fn iscsi_chap_probe_boundaries() {
    let extractor = iscsi_chap::IscsiChapExtractor;
    assert!(matches!(
        extractor.probe(&artifact("iscsi-chap", "incomplete.pcap")),
        Probe::Maybe(reason) if reason.contains("CHAP")
    ));
    assert_eq!(
        extractor.probe(&artifact("sip-digest", "register.pcap")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a capture".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(matches!(
        extractor.probe(&truncated("iscsi-chap", "login.pcap")),
        Probe::Maybe(_)
    ));
    assert!(
        extractor
            .extract(&truncated("iscsi-chap", "login.pcap"))
            .is_err()
    );
    assert!(
        extractor
            .extract(&artifact("iscsi-chap", "incomplete.pcap"))
            .is_err()
    );
}

#[test]
fn snmpv3_extracts_raw_and_captured_messages() {
    let extractor = snmpv3::Snmpv3Extractor;
    assert_eq!(extractor.slug(), "snmpv3");
    for (name, hash) in [
        ("message.bin", "message.hash"),
        ("message.pcap", "message.hash"),
    ] {
        assert!(
            matches!(
                extractor.probe(&artifact("snmpv3", name)),
                Probe::Yes(reason) if reason.contains("SNMPv3")
            ),
            "{name}"
        );
        assert_eq!(
            rendered(extractor.extract(&artifact("snmpv3", name))),
            vec![expected("snmpv3", hash)],
            "{name}"
        );
    }
    let values = extractor
        .extract(&artifact("snmpv3", "sha256.bin"))
        .unwrap();
    assert_eq!(
        values[0].render(&RenderOptions::default()).unwrap(),
        expected("snmpv3", "sha256.hash")
    );
    assert!(
        values[0]
            .modes()
            .iter()
            .any(|mode| matches!(mode, omniex::Mode::Hashcat(26800)))
    );
}

#[test]
fn snmpv3_probe_boundaries() {
    let extractor = snmpv3::Snmpv3Extractor;
    assert!(matches!(
        extractor.probe(&artifact("snmpv3", "unauth.bin")),
        Probe::Maybe(reason) if reason.contains("authentication")
    ));
    assert!(
        extractor
            .extract(&artifact("snmpv3", "unauth.bin"))
            .is_err()
    );
    assert_eq!(
        extractor.probe(&artifact("iscsi-chap", "login.pcap")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not snmp".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(
        extractor
            .extract(&truncated("snmpv3", "message.bin"))
            .is_err()
    );
}

#[test]
fn radius_requires_an_explicit_sidecar() {
    let extractor = radius::RadiusExtractor;
    assert_eq!(extractor.slug(), "radius");
    assert!(matches!(
        extractor.probe(&artifact("radius", "access.pcap")),
        Probe::Maybe(reason) if reason.contains("sidecar")
    ));
    assert!(
        extractor
            .extract(&artifact("radius", "access.pcap"))
            .is_err()
    );

    let secret = std::fs::read(fixture("radius", "shared.secret")).unwrap();
    let with_secret = with_member("radius", "access.pcap", "radius-secret", secret);
    assert!(matches!(
        extractor.probe(&with_secret),
        Probe::Yes(reason) if reason.contains("User-Password")
    ));
    assert_eq!(
        rendered_john(extractor.extract(&with_secret)),
        vec![expected("radius", "access.hash")]
    );

    let salted = Artifact::from_file(&fixture("radius", "access.pcap")).unwrap();
    assert_eq!(
        rendered_john(extractor.extract(&salted)),
        vec![expected("radius", "access.hash")]
    );

    let password = with_member(
        "radius",
        "access.pcap",
        "radius-password",
        b"Passw0rd2".to_vec(),
    );
    assert_eq!(
        rendered_john(extractor.extract(&password)),
        vec![expected("radius", "access.hash").replace("*1*", "*0*")]
    );
}

#[test]
fn radius_probe_boundaries() {
    let extractor = radius::RadiusExtractor;
    assert!(matches!(
        extractor.probe(&artifact("radius", "nopassword.pcap")),
        Probe::Maybe(reason) if reason.contains("User-Password")
    ));
    assert_eq!(
        extractor.probe(&artifact("snmpv3", "message.pcap")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a capture".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(matches!(
        extractor.probe(&truncated("radius", "access.pcap")),
        Probe::Maybe(_)
    ));
}

#[test]
fn tacacs_plus_extracts_encrypted_responses() {
    let extractor = tacacs_plus::TacacsPlusExtractor;
    assert_eq!(extractor.slug(), "tacacs-plus");
    assert!(matches!(
        extractor.probe(&artifact("tacacs-plus", "response.pcap")),
        Probe::Yes(reason) if reason.contains("TACACS+")
    ));
    assert_eq!(
        rendered(extractor.extract(&artifact("tacacs-plus", "response.pcap"))),
        vec![expected("tacacs-plus", "response.hash")]
    );
    assert_eq!(
        rendered(extractor.extract(&artifact("tacacs-plus", "multi.pcap"))),
        lines("tacacs-plus", "multi.hash")
    );
}

#[test]
fn tacacs_plus_probe_boundaries() {
    let extractor = tacacs_plus::TacacsPlusExtractor;
    assert!(matches!(
        extractor.probe(&artifact("tacacs-plus", "plain.pcap")),
        Probe::Maybe(reason) if reason.contains("encrypted")
    ));
    assert_eq!(
        extractor.probe(&artifact("iscsi-chap", "login.pcap")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a capture".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(matches!(
        extractor.probe(&truncated("tacacs-plus", "response.pcap")),
        Probe::Maybe(_)
    ));
}

#[test]
fn sip_digest_extracts_authorization_headers() {
    let extractor = sip_digest::SipDigestExtractor;
    assert_eq!(extractor.slug(), "sip-digest");
    for (name, hash) in [
        ("register.pcap", "register.hash"),
        ("register.pcapng", "register.hash"),
        ("invite.pcap", "invite.hash"),
    ] {
        assert!(
            matches!(
                extractor.probe(&artifact("sip-digest", name)),
                Probe::Yes(reason) if reason.contains("SIP")
            ),
            "{name}"
        );
        assert_eq!(
            rendered(extractor.extract(&artifact("sip-digest", name))),
            vec![expected("sip-digest", hash)],
            "{name}"
        );
    }
    assert_eq!(
        rendered(extractor.extract(&artifact("sip-digest", "multi.pcap"))),
        lines("sip-digest", "multi.hash")
    );
    let values = extractor
        .extract(&artifact("sip-digest", "register.pcap"))
        .unwrap();
    assert!(
        values[0]
            .modes()
            .iter()
            .any(|mode| matches!(mode, omniex::Mode::Hashcat(11400)))
    );
}

#[test]
fn sip_digest_probe_boundaries() {
    let extractor = sip_digest::SipDigestExtractor;
    assert!(matches!(
        extractor.probe(&artifact("sip-digest", "sha256.pcap")),
        Probe::Maybe(reason) if reason.contains("unsupported")
    ));
    assert!(
        extractor
            .extract(&artifact("sip-digest", "sha256.pcap"))
            .is_err()
    );
    assert!(matches!(
        extractor.probe(&artifact("sip-digest", "plain.pcap")),
        Probe::Maybe(reason) if reason.contains("without digest")
    ));
    assert_eq!(
        extractor.probe(&artifact("tacacs-plus", "response.pcap")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"not a capture".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(matches!(
        extractor.probe(&truncated("sip-digest", "register.pcap")),
        Probe::Maybe(_)
    ));
}

#[test]
fn network_extractors_claim_only_their_own_captures() {
    let plain = Artifact::from_bytes("plain", b"plain text with no capture".to_vec());
    for extractor in [
        &iscsi_chap::IscsiChapExtractor as &dyn Extractor,
        &snmpv3::Snmpv3Extractor,
        &radius::RadiusExtractor,
        &tacacs_plus::TacacsPlusExtractor,
        &sip_digest::SipDigestExtractor,
    ] {
        assert_eq!(extractor.probe(&plain), Probe::No, "{}", extractor.slug());
    }

    let owned = [
        (
            "iscsi-chap",
            &artifact("iscsi-chap", "login.pcap"),
            &iscsi_chap::IscsiChapExtractor as &dyn Extractor,
        ),
        (
            "snmpv3",
            &artifact("snmpv3", "message.pcap"),
            &snmpv3::Snmpv3Extractor,
        ),
        (
            "tacacs-plus",
            &artifact("tacacs-plus", "response.pcap"),
            &tacacs_plus::TacacsPlusExtractor,
        ),
        (
            "sip-digest",
            &artifact("sip-digest", "register.pcap"),
            &sip_digest::SipDigestExtractor,
        ),
    ];
    for (slug, capture, owner) in owned {
        assert!(matches!(owner.probe(capture), Probe::Yes(_)), "{slug}");
        for extractor in [
            &iscsi_chap::IscsiChapExtractor as &dyn Extractor,
            &snmpv3::Snmpv3Extractor,
            &radius::RadiusExtractor,
            &tacacs_plus::TacacsPlusExtractor,
            &sip_digest::SipDigestExtractor,
        ] {
            if extractor.slug() == slug {
                continue;
            }
            assert_eq!(
                extractor.probe(capture),
                Probe::No,
                "{} on {slug}",
                extractor.slug()
            );
        }
    }
}
