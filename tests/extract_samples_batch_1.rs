//! Extraction coverage for ENCDataVault vaults and Jetico BestCrypt containers.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, MemorySource};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn contents(kind: &str, name: &str) -> Vec<u8> {
    std::fs::read(fixture(kind, name)).unwrap()
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, contents(kind, name))
}

fn vault(name: &str, companions: &[(&str, &str)]) -> Artifact {
    let mut entry = artifact("encdv", name);
    for (member, file) in companions {
        entry = entry.with_member(*member, MemorySource::from(contents("encdv", file)));
    }
    entry
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

fn probe(slug: &str, artifact: &Artifact) -> omniex::extract::Probe {
    extract::by_slug(slug)
        .expect("extractor is registered")
        .probe(artifact)
}

fn render(hash: &dyn omniex::HashValue, tool: Tool) -> String {
    hash.render(&RenderOptions {
        tool,
        ..RenderOptions::default()
    })
    .expect("render extracted hash")
}

struct Case {
    name: &'static str,
    companions: &'static [(&'static str, &'static str)],
    hash: &'static str,
    mode: u32,
}

#[test]
fn encdv_extracts_every_vault_family() {
    let cases = [
        Case {
            name: "filesystem-v1.dat",
            companions: &[],
            hash: "filesystem-v1.hash",
            mode: 29930,
        },
        Case {
            name: "filesystem-v1-pbkdf2.dat",
            companions: &[("enckey", "enckey-v1-pbkdf2.dat")],
            hash: "filesystem-v1-pbkdf2.hash",
            mode: 29910,
        },
        Case {
            name: "index-v3.dat",
            companions: &[("keychain", "keychain-v3.dat")],
            hash: "index-v3.hash",
            mode: 29940,
        },
        Case {
            name: "index-v3-pbkdf2.dat",
            companions: &[
                ("enckey", "enckey-v3-pbkdf2.dat"),
                ("keychain", "keychain-v3-pbkdf2.dat"),
            ],
            hash: "index-v3-pbkdf2.hash",
            mode: 29920,
        },
    ];

    for case in cases {
        let entry = vault(case.name, case.companions);
        assert!(
            matches!(probe("encdv", &entry), omniex::extract::Probe::Yes(_)),
            "{}",
            case.name
        );
        let hashes = extract::by_slug("encdv")
            .unwrap()
            .extract(&entry)
            .expect("extract ENCDataVault");
        assert_eq!(hashes.len(), 1, "{}", case.name);
        assert_eq!(
            render(hashes[0].as_ref(), Tool::Hashcat),
            expected("encdv", case.hash),
            "{}",
            case.name
        );
        assert!(
            hashes[0].modes().contains(&Mode::Hashcat(case.mode)),
            "{}",
            case.name
        );
    }
}

#[test]
fn encdv_probe_requires_a_structural_header() {
    let extractor = extract::by_slug("encdv").unwrap();
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        omniex::extract::Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );

    let mut damaged = contents("encdv", "filesystem-v1.dat");
    damaged[0] ^= 0xff;
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("damaged", damaged)),
        omniex::extract::Probe::No
    );

    let index = artifact("encdv", "index-v3.dat");
    assert_eq!(probe("encdv", &index), omniex::extract::Probe::No);
    assert!(extractor.extract(&index).is_err());
}

#[test]
fn encdv_rejects_malformed_companions() {
    let short_enckey = Artifact::from_bytes(
        "filesystem-v1-pbkdf2.dat",
        contents("encdv", "filesystem-v1-pbkdf2.dat"),
    )
    .with_member("enckey", MemorySource::from(vec![0u8; 8]));
    assert_eq!(probe("encdv", &short_enckey), omniex::extract::Probe::No);
    assert!(
        extract::by_slug("encdv")
            .unwrap()
            .extract(&short_enckey)
            .is_err()
    );

    let short_keychain = Artifact::from_bytes("index-v3.dat", contents("encdv", "index-v3.dat"))
        .with_member("keychain", MemorySource::from(vec![0u8; 64]));
    assert_eq!(probe("encdv", &short_keychain), omniex::extract::Probe::No);
    assert!(
        extract::by_slug("encdv")
            .unwrap()
            .extract(&short_keychain)
            .is_err()
    );
}

#[test]
fn encdv_auto_detects_and_reports_json() {
    let path = fixture("encdv", "filesystem-v1.dat");
    let auto = omniex().arg("extract").arg(&path).output().unwrap();
    assert!(auto.status.success());
    assert_eq!(
        String::from_utf8_lossy(&auto.stdout).trim_end(),
        expected("encdv", "filesystem-v1.hash")
    );

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "encdv");
    assert_eq!(value[0]["hash"], expected("encdv", "filesystem-v1.hash"));
}

#[test]
fn encdv_does_not_claim_bestcrypt_containers() {
    assert_eq!(
        probe("encdv", &artifact("bestcrypt", "container-openwall.jbc")),
        omniex::extract::Probe::No
    );
}

#[test]
fn bestcrypt_extracts_every_key_slot() {
    for name in ["container-openwall.jbc", "container-password@123.jbc"] {
        let entry = artifact("bestcrypt", name);
        assert!(
            matches!(
                probe("bestcrypt-john", &entry),
                omniex::extract::Probe::Yes(reason)
                    if reason == "BestCrypt keygen container header"
            ),
            "{name}"
        );
        let hashes = extract::by_slug("bestcrypt-john")
            .unwrap()
            .extract(&entry)
            .expect("extract BestCrypt");
        assert_eq!(hashes.len(), 1, "{name}");
        assert_eq!(
            render(hashes[0].as_ref(), Tool::John),
            expected("bestcrypt", &name.replace(".jbc", ".hash")),
            "{name}"
        );
        assert!(
            hashes[0].modes().contains(&Mode::John("BestCrypt")),
            "{name}"
        );
    }
}

#[test]
fn bestcrypt_probe_requires_the_keygen_header() {
    let extractor = extract::by_slug("bestcrypt-john").unwrap();
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        omniex::extract::Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );

    let data = contents("bestcrypt", "container-openwall.jbc");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("truncated", data[..1024].to_vec())),
        omniex::extract::Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", data[..1024].to_vec()))
            .is_err()
    );

    let mut encrypted = data.clone();
    encrypted[43..54].copy_from_slice(b"NotBCKeyGen");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("encrypted", encrypted)),
        omniex::extract::Probe::No
    );

    let mut bad_cipher = data;
    bad_cipher[128..132].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad-cipher", bad_cipher)),
        omniex::extract::Probe::No
    );
}

#[test]
fn bestcrypt_auto_detects_and_honors_json() {
    let path = fixture("bestcrypt", "container-openwall.jbc");
    let auto = omniex()
        .arg("extract")
        .arg(&path)
        .args(["--format", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());
    assert_eq!(
        String::from_utf8_lossy(&auto.stdout).trim_end(),
        expected("bestcrypt", "container-openwall.hash")
    );

    let json = omniex()
        .arg("extract")
        .arg("--type")
        .arg("bestcrypt-john")
        .args(["--format", "john"])
        .arg("--json")
        .arg(&path)
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "bestcrypt-john");
    assert_eq!(
        value[0]["hash"],
        expected("bestcrypt", "container-openwall.hash")
    );
}

#[test]
fn bestcrypt_does_not_claim_encdv_vaults() {
    assert_eq!(
        probe("bestcrypt-john", &artifact("encdv", "filesystem-v1.dat")),
        omniex::extract::Probe::No
    );
}

#[test]
fn extracted_bestcrypt_values_round_trip_through_the_registry() {
    let entry = artifact("bestcrypt", "container-openwall.jbc");
    let value = &extract::by_slug("bestcrypt-john")
        .unwrap()
        .extract(&entry)
        .unwrap()[0];
    let rendered = value
        .render(&RenderOptions {
            tool: Tool::John,
            ..RenderOptions::default()
        })
        .unwrap();
    let parsed = parse_bestcrypt(&rendered);
    assert_eq!(
        parsed
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        rendered
    );
}

fn parse_bestcrypt(hash: &str) -> Box<dyn omniex::HashValue> {
    omniex::registry::parse(
        omniex::registry::by_slug("bestcrypt-john").unwrap(),
        hash,
        &omniex::ParseOptions {
            tool: Tool::John,
            ..omniex::ParseOptions::default()
        },
    )
    .unwrap()
}

#[test]
fn encdv_cli_attaches_a_named_companion() {
    let companion = format!(
        "enckey={}",
        fixture("encdv", "enckey-v1-pbkdf2.dat").display()
    );
    let output = omniex()
        .arg("extract")
        .arg("--type")
        .arg("encdv")
        .arg("--format")
        .arg("hashcat")
        .arg("--companion")
        .arg(companion)
        .arg(fixture("encdv", "filesystem-v1-pbkdf2.dat"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        expected("encdv", "filesystem-v1-pbkdf2.hash")
    );
}
