//! MetaMask, Exodus, Bisq, and Cardano wallet extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

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

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

#[test]
fn wallet_probes_are_structural() {
    for (slug, kind, name) in [
        ("metamask", "metamask", "vault.json"),
        ("metamask-mobile", "metamask-mobile", "vault.json"),
        ("exodus", "exodus", "seed.seco"),
        ("bisq", "bisq", "bisq.wallet"),
        ("cardano-payload", "cardano", "secret.key"),
    ] {
        let extractor = extract::by_slug(slug).expect("wallet extractor");
        assert!(matches!(
            extractor.probe(&artifact(kind, name)),
            Probe::Yes(_)
        ));
        assert!(
            matches!(
                extractor.probe(&Artifact::from_bytes("plain", b"not a wallet".to_vec())),
                Probe::No
            ),
            "{slug}"
        );
    }
}

#[test]
fn metamask_desktop_and_mobile_render_their_serializations() {
    let desktop = extract::by_slug("metamask").expect("MetaMask extractor");
    assert_eq!(
        desktop
            .extract(&artifact("metamask", "vault.json"))
            .unwrap()[0]
            .render(&RenderOptions::default())
            .unwrap(),
        expected("metamask", "vault.hash")
    );

    let mobile = extract::by_slug("metamask-mobile").expect("MetaMask mobile extractor");
    assert_eq!(
        mobile
            .extract(&artifact("metamask-mobile", "vault.json"))
            .unwrap()[0]
            .render(&RenderOptions::default())
            .unwrap(),
        expected("metamask-mobile", "vault.hash")
    );

    assert!(
        desktop
            .extract(&artifact("metamask-mobile", "vault.json"))
            .is_err()
    );
    assert!(mobile.extract(&artifact("metamask", "vault.json")).is_err());
}

#[test]
fn exodus_bisq_and_cardano_extract_reference_hashes() {
    let exodus = extract::by_slug("exodus").expect("Exodus extractor");
    assert_eq!(
        exodus.extract(&artifact("exodus", "seed.seco")).unwrap()[0]
            .render(&RenderOptions::default())
            .unwrap(),
        expected("exodus", "seed.hash")
    );

    let bisq = extract::by_slug("bisq").expect("Bisq extractor");
    assert_eq!(
        bisq.extract(&artifact("bisq", "bisq.wallet")).unwrap()[0]
            .render(&RenderOptions::default())
            .unwrap(),
        expected("bisq", "bisq.hash")
    );

    let cardano = extract::by_slug("cardano-payload").expect("Cardano extractor");
    assert_eq!(
        cardano.extract(&artifact("cardano", "secret.key")).unwrap()[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        expected("cardano", "secret.hash")
    );
}

#[test]
fn wallet_files_auto_detect_without_type_hints() {
    for (kind, name, format) in [
        ("metamask", "vault.json", "hashcat"),
        ("metamask-mobile", "vault.json", "hashcat"),
        ("exodus", "seed.seco", "hashcat"),
        ("bisq", "bisq.wallet", "hashcat"),
    ] {
        let output = omniex()
            .arg("extract")
            .arg(fixture(kind, name))
            .args(["--tool", format])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = omniex()
        .arg("extract")
        .arg(fixture("cardano", "secret.key"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        expected("cardano", "secret.hash")
    );
}

#[test]
fn truncated_wallets_are_rejected() {
    for (slug, kind, name) in [
        ("metamask", "metamask", "vault.json"),
        ("metamask-mobile", "metamask-mobile", "vault.json"),
        ("exodus", "exodus", "seed.seco"),
        ("bisq", "bisq", "bisq.wallet"),
        ("cardano-payload", "cardano", "secret.key"),
    ] {
        let data = std::fs::read(fixture(kind, name)).unwrap();
        let extractor = extract::by_slug(slug).expect("wallet extractor");
        assert!(
            extractor
                .extract(&Artifact::from_bytes(name, data[..data.len() / 2].to_vec()))
                .is_err(),
            "{slug}"
        );
    }
}
