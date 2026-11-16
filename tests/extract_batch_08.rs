//! Batch 08 wallet extraction: Blockchain second password, Dogechain, Tezos,
//! Keplr, and Stargazer Stellar.

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

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn scratch(name: &str, contents: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("batch08")
        .join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, contents).unwrap();
    path
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn rendered(hashes: &[Box<dyn omniex::HashValue>], tool: Tool) -> Vec<String> {
    hashes
        .iter()
        .map(|hash| {
            hash.render(&RenderOptions {
                tool,
                ..Default::default()
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn probes_are_structural() {
    for (slug, kind, name) in [
        ("blockchain-second", "blockchain-second", "wallet.json"),
        ("dogechain", "dogechain", "wallet.json"),
        ("tezos", "tezos", "wallet.json"),
        ("keplr", "keplr", "000003.log"),
        ("stellar", "stellar", "local-storage.json"),
    ] {
        let extractor = extract::by_slug(slug).expect("extractor is registered");
        assert!(
            matches!(extractor.probe(&artifact(kind, name)), Probe::Yes(_)),
            "{slug}"
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
            Probe::No,
            "{slug} empty"
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("text", b"not a wallet".to_vec())),
            Probe::No,
            "{slug} text"
        );
    }

    let keplr = extract::by_slug("keplr").unwrap();
    assert!(matches!(
        keplr.probe(&artifact("keplr", "keyring.json")),
        Probe::Yes(reason) if reason == "Keplr keyring JSON"
    ));
    let blockchain = extract::by_slug("blockchain-second").unwrap();
    assert!(matches!(
        blockchain.probe(&artifact("blockchain-second", "second-password.txt")),
        Probe::Yes(_)
    ));
}

#[test]
fn extractors_match_their_fixtures() {
    let blockchain = extract::by_slug("blockchain-second").unwrap();
    assert_eq!(
        rendered(
            &blockchain
                .extract(&artifact("blockchain-second", "wallet.json"))
                .unwrap(),
            Tool::Hashcat
        ),
        [expected("blockchain-second", "wallet.hash")]
    );
    assert_eq!(
        rendered(
            &blockchain
                .extract(&artifact("blockchain-second", "second-password.txt"))
                .unwrap(),
            Tool::Hashcat
        ),
        [expected("blockchain-second", "wallet.hash")]
    );

    let dogechain = extract::by_slug("dogechain").unwrap();
    let hashes = dogechain
        .extract(&artifact("dogechain", "wallet.json"))
        .unwrap();
    assert_eq!(
        rendered(&hashes, Tool::Hashcat),
        [expected("dogechain", "wallet.hash")]
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(32500)));

    let stellar = extract::by_slug("stellar").unwrap();
    let hashes = stellar
        .extract(&artifact("stellar", "local-storage.json"))
        .unwrap();
    assert_eq!(
        rendered(&hashes, Tool::Hashcat),
        [expected("stellar", "wallet.hash")]
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(25500)));

    let tezos = extract::by_slug("tezos").unwrap();
    let hashes = tezos.extract(&artifact("tezos", "wallet.json")).unwrap();
    assert_eq!(
        rendered(&hashes, Tool::John),
        [expected("tezos", "wallet.hash")]
    );

    let keplr = extract::by_slug("keplr").unwrap();
    let hashes = keplr.extract(&artifact("keplr", "000003.log")).unwrap();
    assert_eq!(
        rendered(&hashes, Tool::John),
        [expected("keplr", "wallet.hash")]
    );
    let json = keplr.extract(&artifact("keplr", "keyring.json")).unwrap();
    assert_eq!(
        rendered(&json, Tool::John),
        [expected("keplr", "wallet.hash")]
    );
    let table = keplr.extract(&artifact("keplr", "wallet.ldb")).unwrap();
    assert_eq!(
        rendered(&table, Tool::John),
        [expected("keplr", "wallet.hash")]
    );
}

#[test]
fn wallet_files_auto_detect_without_type_hints() {
    for (kind, name, format) in [
        ("blockchain-second", "second-password.txt", "hashcat"),
        ("dogechain", "wallet.json", "hashcat"),
        ("stellar", "local-storage.json", "hashcat"),
        ("keplr", "000003.log", "john"),
        ("tezos", "wallet.json", "john"),
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

    let wallet = omniex()
        .arg("extract")
        .arg(fixture("blockchain-second", "wallet.json"))
        .output()
        .unwrap();
    assert!(!wallet.status.success());
}

#[test]
fn john_only_wallets_need_their_format() {
    for (kind, name, slug) in [
        ("tezos", "wallet.json", "tezos"),
        ("keplr", "keyring.json", "keplr"),
    ] {
        let output = omniex()
            .arg("extract")
            .arg(fixture(kind, name))
            .args(["--type", slug, "--tool", "john"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{kind}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim_end(),
            expected(kind, "wallet.hash")
        );
    }
}

#[test]
fn all_extracts_recognized_wallets() {
    for (kind, name, format, slug) in [
        (
            "blockchain-second",
            "second-password.txt",
            "hashcat",
            "blockchain-second",
        ),
        ("dogechain", "wallet.json", "hashcat", "dogechain"),
        ("stellar", "local-storage.json", "hashcat", "stellar"),
        ("keplr", "000003.log", "john", "keplr"),
        ("tezos", "wallet.json", "john", "tezos"),
    ] {
        let output = omniex()
            .arg("extract")
            .arg("--all")
            .arg(fixture(kind, name))
            .args(["--tool", format, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["type"] == slug),
            "{kind}"
        );
    }
}

#[test]
fn whole_artifacts_are_scanned_for_every_record() {
    let blockchain = std::fs::read_to_string(fixture("blockchain-second", "wallet.json")).unwrap();
    let wallet: serde_json::Value = serde_json::from_str(&blockchain).unwrap();
    let path = scratch(
        "blockchain-many.json",
        &serde_json::to_string(&serde_json::json!([wallet, wallet])).unwrap(),
    );
    let hashes = extract::by_slug("blockchain-second")
        .unwrap()
        .extract(&Artifact::from_file(&path).unwrap())
        .unwrap();
    assert_eq!(hashes.len(), 2);

    let doge = std::fs::read_to_string(fixture("dogechain", "wallet.json")).unwrap();
    let wallet: serde_json::Value = serde_json::from_str(&doge).unwrap();
    let mut second = wallet.clone();
    second["pbkdf2_iterations"] = serde_json::json!(8000);
    let path = scratch(
        "dogechain-many.json",
        &serde_json::to_string(&serde_json::json!([wallet, second])).unwrap(),
    );
    let hashes = extract::by_slug("dogechain")
        .unwrap()
        .extract(&Artifact::from_file(&path).unwrap())
        .unwrap();
    assert_eq!(hashes.len(), 2);

    let tezos = std::fs::read_to_string(fixture("tezos", "wallet.json")).unwrap();
    let wallet: serde_json::Value = serde_json::from_str(&tezos).unwrap();
    let path = scratch(
        "tezos-many.json",
        &serde_json::to_string(&serde_json::json!({"wallets": [wallet, wallet]})).unwrap(),
    );
    let hashes = extract::by_slug("tezos")
        .unwrap()
        .extract(&Artifact::from_file(&path).unwrap())
        .unwrap();
    assert_eq!(hashes.len(), 2);

    let stellar = std::fs::read_to_string(fixture("stellar", "local-storage.json")).unwrap();
    let storage: serde_json::Value = serde_json::from_str(&stellar).unwrap();
    let path = scratch(
        "stellar-many.json",
        &serde_json::to_string(&serde_json::json!({
            "one": storage["key.GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"],
            "two": storage["key.GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"],
        }))
        .unwrap(),
    );
    let hashes = extract::by_slug("stellar")
        .unwrap()
        .extract(&Artifact::from_file(&path).unwrap())
        .unwrap();
    assert_eq!(hashes.len(), 2);

    let keplr = std::fs::read_to_string(fixture("keplr", "keyring.json")).unwrap();
    let store: serde_json::Value = serde_json::from_str(&keplr).unwrap();
    let mut second = store.clone();
    let ciphertext = format!("{}00", store["crypto"]["ciphertext"].as_str().unwrap());
    second["crypto"]["ciphertext"] = serde_json::json!(ciphertext);
    let path = scratch(
        "keplr-many.json",
        &serde_json::to_string(&serde_json::json!([store, second])).unwrap(),
    );
    let hashes = extract::by_slug("keplr")
        .unwrap()
        .extract(&Artifact::from_file(&path).unwrap())
        .unwrap();
    assert_eq!(hashes.len(), 2);
}

#[test]
fn truncated_and_empty_artifacts_are_rejected() {
    for (slug, kind, name) in [
        ("blockchain-second", "blockchain-second", "wallet.json"),
        ("dogechain", "dogechain", "wallet.json"),
        ("tezos", "tezos", "wallet.json"),
        ("keplr", "keplr", "000003.log"),
        ("stellar", "stellar", "local-storage.json"),
    ] {
        let extractor = extract::by_slug(slug).unwrap();
        let data = std::fs::read(fixture(kind, name)).unwrap();
        assert!(
            extractor
                .extract(&Artifact::from_bytes(name, data[..data.len() / 2].to_vec()))
                .is_err(),
            "{slug} truncated"
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes(name, Vec::new()))
                .is_err(),
            "{slug} empty"
        );
    }
}

#[test]
fn malformed_wallets_are_rejected() {
    let bad_blob = base64_of(&[&b"bs:"[..], &[0; 32], &[1; 16], &[0; 4], &[0; 4]].concat());
    let blockchain = extract::by_slug("blockchain-second").unwrap();
    assert_eq!(
        blockchain.probe(&Artifact::from_bytes("bad.txt", bad_blob.into_bytes())),
        Probe::No
    );
    assert!(
        blockchain
            .extract(&Artifact::from_bytes("bad.txt", b"not json".to_vec()))
            .is_err()
    );

    let doge = std::fs::read_to_string(fixture("dogechain", "wallet.json")).unwrap();
    let mut wallet: serde_json::Value = serde_json::from_str(&doge).unwrap();
    wallet["cipher"] = serde_json::json!("AES-GCM");
    let path = scratch("dogechain-gcm.json", &wallet.to_string());
    assert!(
        extract::by_slug("dogechain")
            .unwrap()
            .extract(&Artifact::from_file(&path).unwrap())
            .is_err()
    );

    let tezos = std::fs::read_to_string(fixture("tezos", "wallet.json")).unwrap();
    let mut wallet: serde_json::Value = serde_json::from_str(&tezos).unwrap();
    let address = wallet["pkh"].as_str().unwrap();
    let mut changed = address.to_owned();
    changed.pop();
    changed.push('S');
    wallet["pkh"] = serde_json::json!(changed);
    let path = scratch("tezos-bad-address.json", &wallet.to_string());
    assert!(
        extract::by_slug("tezos")
            .unwrap()
            .extract(&Artifact::from_file(&path).unwrap())
            .is_err()
    );

    let stellar = std::fs::read_to_string(fixture("stellar", "local-storage.json")).unwrap();
    let mut storage: serde_json::Value = serde_json::from_str(&stellar).unwrap();
    let key = "key.GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let mut record: serde_json::Value =
        serde_json::from_str(storage[key].as_str().unwrap()).unwrap();
    record[2][0] = serde_json::json!("AAAA");
    storage[key] = serde_json::json!(record.to_string());
    let path = scratch("stellar-bad-iv.json", &storage.to_string());
    assert!(
        extract::by_slug("stellar")
            .unwrap()
            .extract(&Artifact::from_file(&path).unwrap())
            .is_err()
    );

    let keplr = std::fs::read_to_string(fixture("keplr", "keyring.json")).unwrap();
    let mut store: serde_json::Value = serde_json::from_str(&keplr).unwrap();
    store["crypto"]["kdfparams"]["n"] = serde_json::json!(1024);
    let path = scratch("keplr-bad-params.json", &store.to_string());
    assert!(
        extract::by_slug("keplr")
            .unwrap()
            .extract(&Artifact::from_file(&path).unwrap())
            .is_err()
    );
}

#[test]
fn wrong_types_are_rejected() {
    let blockchain = extract::by_slug("blockchain-second").unwrap();
    let dogechain = extract::by_slug("dogechain").unwrap();
    let tezos = extract::by_slug("tezos").unwrap();
    let keplr = extract::by_slug("keplr").unwrap();
    let stellar = extract::by_slug("stellar").unwrap();

    assert!(
        blockchain
            .extract(&artifact("dogechain", "wallet.json"))
            .is_err()
    );
    assert!(
        dogechain
            .extract(&artifact("blockchain-second", "wallet.json"))
            .is_err()
    );
    assert!(
        tezos
            .extract(&artifact("stellar", "local-storage.json"))
            .is_err()
    );
    assert!(stellar.extract(&artifact("tezos", "wallet.json")).is_err());
    assert!(
        keplr
            .extract(&artifact("dogechain", "wallet.json"))
            .is_err()
    );
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn network_probe(slug: &str, kind: &str, name: &str) -> Probe {
    extract::by_slug(slug)
        .expect("extractor is registered")
        .probe(&artifact(kind, name))
}

fn expected_lines(kind: &str, name: &str) -> Vec<String> {
    expected(kind, name)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[test]
fn network_probes_require_structural_evidence() {
    for (slug, kind, name) in [
        ("krb4", "krb4", "asrep.pcap"),
        ("netntlmv1", "netntlmv1", "exchange.pcap"),
        ("netntlmv2", "netntlmv2", "exchange.pcap"),
        ("mschapv2-naive", "mschapv2-naive", "exchange.pcap"),
        ("chap", "chap", "ppp.pcap"),
        ("chap", "chap", "iscsi.pcap"),
    ] {
        assert!(
            matches!(network_probe(slug, kind, name), Probe::Yes(_)),
            "{slug} {name}"
        );
        assert_eq!(
            extract::by_slug(slug)
                .unwrap()
                .probe(&Artifact::from_bytes("empty", Vec::new())),
            Probe::No,
            "{slug} empty"
        );
    }

    for (slug, kind, name) in [
        ("netntlmv1", "netntlmv2", "exchange.pcap"),
        ("netntlmv2", "netntlmv1", "exchange.pcap"),
        ("mschapv2-naive", "chap", "ppp.pcap"),
        ("chap", "mschapv2-naive", "exchange.pcap"),
        ("netntlmv1", "krb4", "asrep.pcap"),
    ] {
        assert_eq!(network_probe(slug, kind, name), Probe::No, "{slug} {name}");
    }

    for slug in ["krb4", "netntlmv1", "netntlmv2", "mschapv2-naive", "chap"] {
        let extractor = extract::by_slug(slug).unwrap();
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
            Probe::No,
            "{slug} empty"
        );
        assert_eq!(
            extractor.probe(&Artifact::from_bytes(
                "text",
                b"not a network exchange".to_vec()
            )),
            Probe::No,
            "{slug} text"
        );
    }
}

#[test]
fn network_extractors_match_their_fixtures() {
    let krb4 = extract::by_slug("krb4").unwrap();
    assert_eq!(
        rendered(
            &krb4.extract(&artifact("krb4", "asrep.pcap")).unwrap(),
            Tool::John
        ),
        [expected("krb4", "asrep.hash")]
    );

    let v1 = extract::by_slug("netntlmv1").unwrap();
    assert_eq!(
        rendered(
            &v1.extract(&artifact("netntlmv1", "exchange.pcap")).unwrap(),
            Tool::Hashcat
        ),
        [expected("netntlmv1", "exchange.hash")]
    );

    let v2 = extract::by_slug("netntlmv2").unwrap();
    assert_eq!(
        rendered(
            &v2.extract(&artifact("netntlmv2", "exchange.pcap")).unwrap(),
            Tool::Hashcat
        ),
        [expected("netntlmv2", "exchange.hash")]
    );
    assert_eq!(
        rendered(
            &v2.extract(&artifact("netntlmv2", "exchange.pcap")).unwrap(),
            Tool::John
        ),
        [expected("netntlmv2", "exchange.hash")]
    );

    let mschap = extract::by_slug("mschapv2-naive").unwrap();
    assert_eq!(
        rendered(
            &mschap
                .extract(&artifact("mschapv2-naive", "exchange.pcap"))
                .unwrap(),
            Tool::John
        ),
        [expected("mschapv2-naive", "exchange.hash")]
    );

    let chap = extract::by_slug("chap").unwrap();
    assert_eq!(
        rendered(
            &chap.extract(&artifact("chap", "ppp.pcap")).unwrap(),
            Tool::John
        ),
        [expected("chap", "ppp.hash")]
    );
    assert_eq!(
        rendered(
            &chap.extract(&artifact("chap", "iscsi.pcap")).unwrap(),
            Tool::John
        ),
        [expected("chap", "iscsi.hash")]
    );
}

#[test]
fn network_artifacts_yield_every_record() {
    for (slug, kind, name, expected_name, tool) in [
        ("krb4", "krb4", "multi.pcap", "multi.hash", Tool::John),
        (
            "netntlmv1",
            "netntlmv1",
            "multi.pcap",
            "multi.hash",
            Tool::Hashcat,
        ),
        (
            "netntlmv2",
            "netntlmv2",
            "multi.pcap",
            "multi.hash",
            Tool::Hashcat,
        ),
        (
            "mschapv2-naive",
            "mschapv2-naive",
            "multi.pcap",
            "multi.hash",
            Tool::John,
        ),
        ("chap", "chap", "multi.pcap", "multi.hash", Tool::John),
    ] {
        let hashes = extract::by_slug(slug)
            .unwrap()
            .extract(&artifact(kind, name))
            .unwrap();
        assert_eq!(
            sorted(rendered(&hashes, tool)),
            sorted(expected_lines(kind, expected_name)),
            "{slug}"
        );
    }
}

#[test]
fn network_artifacts_auto_detect_and_accept_explicit_types() {
    for (slug, kind, name, format, expected_name) in [
        ("krb4", "krb4", "asrep.pcap", "john", "asrep.hash"),
        (
            "netntlmv1",
            "netntlmv1",
            "exchange.pcap",
            "hashcat",
            "exchange.hash",
        ),
        (
            "netntlmv2",
            "netntlmv2",
            "exchange.pcap",
            "hashcat",
            "exchange.hash",
        ),
        (
            "mschapv2-naive",
            "mschapv2-naive",
            "exchange.pcap",
            "john",
            "exchange.hash",
        ),
        ("chap", "chap", "ppp.pcap", "john", "ppp.hash"),
        ("chap", "chap", "iscsi.pcap", "john", "iscsi.hash"),
    ] {
        let auto = omniex()
            .arg("extract")
            .arg(fixture(kind, name))
            .args(["--tool", format])
            .output()
            .unwrap();
        assert!(
            auto.status.success(),
            "{slug} auto: {}",
            String::from_utf8_lossy(&auto.stderr)
        );

        let explicit = omniex()
            .arg("extract")
            .arg(fixture(kind, name))
            .args(["--type", slug, "--tool", format])
            .output()
            .unwrap();
        assert!(explicit.status.success(), "{slug} explicit");
        assert_eq!(
            String::from_utf8_lossy(&explicit.stdout).trim_end(),
            expected(kind, expected_name),
            "{slug}"
        );
    }
}

#[test]
fn network_all_extracts_recognized_exchanges() {
    for (kind, name, format, slug) in [
        ("krb4", "asrep.pcap", "john", "krb4"),
        ("netntlmv1", "exchange.pcap", "hashcat", "netntlmv1"),
        ("netntlmv2", "exchange.pcap", "hashcat", "netntlmv2"),
        ("mschapv2-naive", "exchange.pcap", "john", "mschapv2-naive"),
        ("chap", "ppp.pcap", "john", "chap"),
        ("chap", "iscsi.pcap", "john", "chap"),
    ] {
        let output = omniex()
            .arg("extract")
            .arg("--all")
            .arg(fixture(kind, name))
            .args(["--tool", format, "--format", "json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            value["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["type"] == slug),
            "{kind}"
        );
    }
}

#[test]
fn truncated_and_empty_network_artifacts_are_rejected() {
    for (slug, kind, name) in [
        ("krb4", "krb4", "asrep.pcap"),
        ("netntlmv1", "netntlmv1", "exchange.pcap"),
        ("netntlmv2", "netntlmv2", "exchange.pcap"),
        ("mschapv2-naive", "mschapv2-naive", "exchange.pcap"),
        ("chap", "chap", "ppp.pcap"),
        ("chap", "chap", "iscsi.pcap"),
    ] {
        let extractor = extract::by_slug(slug).unwrap();
        let data = std::fs::read(fixture(kind, name)).unwrap();
        assert!(
            extractor
                .extract(&Artifact::from_bytes(name, data[..data.len() / 2].to_vec()))
                .is_err(),
            "{slug} truncated"
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes(name, Vec::new()))
                .is_err(),
            "{slug} empty"
        );
    }
}

#[test]
fn wrong_network_types_are_rejected() {
    for (slug, kind, name) in [
        ("krb4", "netntlmv1", "exchange.pcap"),
        ("netntlmv1", "netntlmv2", "exchange.pcap"),
        ("netntlmv2", "netntlmv1", "exchange.pcap"),
        ("mschapv2-naive", "chap", "ppp.pcap"),
        ("chap", "mschapv2-naive", "exchange.pcap"),
    ] {
        assert!(
            extract::by_slug(slug)
                .unwrap()
                .extract(&artifact(kind, name))
                .is_err(),
            "{slug} accepted {kind}"
        );
    }
}

#[test]
fn malformed_network_captures_probe_maybe() {
    for (slug, kind, name) in [
        ("krb4", "krb4", "asrep.pcap"),
        ("netntlmv1", "netntlmv1", "exchange.pcap"),
        ("netntlmv2", "netntlmv2", "exchange.pcap"),
        ("mschapv2-naive", "mschapv2-naive", "exchange.pcap"),
        ("chap", "chap", "ppp.pcap"),
    ] {
        let data = std::fs::read(fixture(kind, name)).unwrap();
        assert!(
            matches!(
                extract::by_slug(slug)
                    .unwrap()
                    .probe(&Artifact::from_bytes(name, data[..10].to_vec())),
                Probe::Maybe(_)
            ),
            "{slug} truncated capture"
        );
    }

    let malformed = b"\xff\x03\xc2\x23\x01\x00\x00\x15\x10".to_vec();
    assert!(matches!(
        extract::by_slug("mschapv2-naive")
            .unwrap()
            .probe(&Artifact::from_bytes("ppp", malformed)),
        Probe::Maybe(_)
    ));
}
