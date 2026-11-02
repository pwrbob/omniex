//! cryptoSafe, GNOME Keyring, Mozilla, and Armory extraction.

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

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn probes_are_structural() {
    for (slug, kind, name) in [
        ("keyring", "keyring", "Default.keyring"),
        ("mozilla-key3", "mozilla-key3", "key3.db"),
        ("mozilla-key4", "mozilla-key4", "key4.db"),
        ("armory", "armory", "test.wallet"),
    ] {
        let extractor = extract::by_slug(slug).expect("extractor");
        assert!(
            matches!(extractor.probe(&artifact(kind, name)), Probe::Yes(_)),
            "{slug}"
        );
        assert!(
            matches!(
                extractor.probe(&Artifact::from_bytes("plain", b"not a wallet".to_vec())),
                Probe::No
            ),
            "{slug}"
        );
    }

    let cryptosafe = extract::by_slug("cryptosafe").expect("cryptoSafe extractor");
    assert!(matches!(
        cryptosafe.probe(&artifact("cryptosafe", "vault.b64")),
        Probe::Maybe(_)
    ));
    assert!(!cryptosafe.exact());
    assert_eq!(
        cryptosafe.probe(&Artifact::from_bytes("bad", b"not base64!".to_vec())),
        Probe::No
    );
}

#[test]
fn extractors_match_their_fixtures() {
    for (slug, kind, name, hash, tool) in [
        (
            "cryptosafe",
            "cryptosafe",
            "vault.b64",
            "vault.hash",
            Tool::John,
        ),
        (
            "keyring",
            "keyring",
            "Default.keyring",
            "Default.hash",
            Tool::John,
        ),
        (
            "mozilla-key3",
            "mozilla-key3",
            "key3.db",
            "key3.hash",
            Tool::Hashcat,
        ),
        (
            "mozilla-key4",
            "mozilla-key4",
            "key4.db",
            "key4.hash",
            Tool::Hashcat,
        ),
        (
            "mozilla-key4",
            "mozilla-key4",
            "key4-sha384.db",
            "key4-sha384.hash",
            Tool::Hashcat,
        ),
        ("armory", "armory", "test.wallet", "test.hash", Tool::John),
    ] {
        let extractor = extract::by_slug(slug).expect("extractor");
        let hashes = extractor.extract(&artifact(kind, name)).expect("extract");
        assert_eq!(hashes.len(), 1, "{slug}");
        assert_eq!(
            hashes[0]
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .unwrap(),
            expected(kind, hash),
            "{slug}"
        );
    }
}

#[test]
fn keyring_and_armory_scan_every_record() {
    let keyring = extract::by_slug("keyring").expect("keyring extractor");
    let mut data = std::fs::read(fixture("keyring", "Default.keyring")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = keyring
        .extract(&Artifact::from_bytes("two.keyring", data))
        .unwrap();
    assert_eq!(hashes.len(), 2);

    let armory = extract::by_slug("armory").expect("Armory extractor");
    let mut wallet = std::fs::read(fixture("armory", "test.wallet")).unwrap();
    let entry = wallet[2107..].to_vec();
    wallet.extend_from_slice(&entry);
    let hashes = armory
        .extract(&Artifact::from_bytes("two.wallet", wallet))
        .unwrap();
    assert_eq!(hashes.len(), 2);
}

#[test]
fn extractors_reject_wrong_types_and_truncated_input() {
    let keyring = extract::by_slug("keyring").expect("keyring extractor");
    assert!(
        keyring
            .extract(&artifact("mozilla-key3", "key3.db"))
            .is_err()
    );

    let key3 = extract::by_slug("mozilla-key3").expect("key3 extractor");
    assert!(key3.extract(&artifact("mozilla-key4", "key4.db")).is_err());

    let key4 = extract::by_slug("mozilla-key4").expect("key4 extractor");
    assert!(key4.extract(&artifact("mozilla-key3", "key3.db")).is_err());

    let armory = extract::by_slug("armory").expect("Armory extractor");
    assert!(
        armory
            .extract(&artifact("keyring", "Default.keyring"))
            .is_err()
    );

    for (slug, kind, name) in [
        ("keyring", "keyring", "Default.keyring"),
        ("mozilla-key3", "mozilla-key3", "key3.db"),
        ("mozilla-key4", "mozilla-key4", "key4.db"),
        ("armory", "armory", "test.wallet"),
    ] {
        let extractor = extract::by_slug(slug).expect("extractor");
        let data = std::fs::read(fixture(kind, name)).unwrap();
        let truncated = Artifact::from_bytes("truncated", data[..data.len() / 2].to_vec());
        assert_eq!(extractor.probe(&truncated), Probe::No, "{slug}");
        assert!(extractor.extract(&truncated).is_err(), "{slug}");
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
            Probe::No,
            "{slug}"
        );
    }
}

#[test]
fn cli_auto_detects_signed_formats_and_requires_type_for_cryptosafe() {
    for (kind, name, slug, format) in [
        ("keyring", "Default.keyring", "keyring", "john"),
        ("mozilla-key3", "key3.db", "mozilla-key3", "hashcat"),
        ("mozilla-key4", "key4.db", "mozilla-key4", "hashcat"),
    ] {
        let output = omniex()
            .arg("extract")
            .arg(fixture(kind, name))
            .arg("--format")
            .arg(format)
            .arg("--json")
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value[0]["type"], slug);
    }

    let armory = omniex()
        .arg("extract")
        .arg(fixture("armory", "test.wallet"))
        .arg("--type")
        .arg("armory")
        .arg("--format")
        .arg("john")
        .arg("--json")
        .output()
        .unwrap();
    assert!(armory.status.success());
    let value: serde_json::Value = serde_json::from_slice(&armory.stdout).unwrap();
    assert_eq!(value[0]["type"], "armory");

    let auto = omniex()
        .arg("extract")
        .arg(fixture("cryptosafe", "vault.b64"))
        .output()
        .unwrap();
    assert!(!auto.status.success());

    let explicit = omniex()
        .arg("extract")
        .arg(fixture("cryptosafe", "vault.b64"))
        .arg("--type")
        .arg("cryptosafe")
        .arg("--format")
        .arg("john")
        .arg("--json")
        .output()
        .unwrap();
    assert!(explicit.status.success());
    let value: serde_json::Value = serde_json::from_slice(&explicit.stdout).unwrap();
    assert_eq!(value[0]["type"], "cryptosafe");

    let all = omniex()
        .arg("extract")
        .arg(fixture("cryptosafe", "vault.b64"))
        .arg("--all")
        .output()
        .unwrap();
    assert!(!all.status.success());
}

#[test]
fn cli_renders_john_serializations() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("armory", "test.wallet"))
        .arg("--type")
        .arg("armory")
        .arg("--format")
        .arg("john")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim_end(),
        expected("armory", "test.hash")
    );

    let output = omniex()
        .arg("extract")
        .arg(fixture("mozilla-key3", "key3.db"))
        .arg("--format")
        .arg("john")
        .output()
        .unwrap();
    assert!(!output.status.success());
}
