//! Hashed SSH known_hosts extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, ExtractError, Extracted, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/known-hosts")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes(
        "known_hosts",
        std::fs::read(fixture("known_hosts")).expect("read known_hosts"),
    )
}

fn extract_error(result: Result<Extracted, ExtractError>) -> ExtractError {
    match result {
        Ok(_) => panic!("expected extraction to fail"),
        Err(error) => error,
    }
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn known_hosts_probe_requires_a_valid_hashed_entry() {
    let extractor = extract::by_slug("known-hosts").expect("known_hosts extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "hashed SSH known_hosts entry"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "plain",
            b"host ssh-rsa AAAA\n".to_vec()
        )),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "bad-salt",
            b"|1|not-base64|I9L3FH6RGefWIFb0Po74BVN3Fto= host\n".to_vec()
        )),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn known_hosts_extracts_every_hashed_entry() {
    let extractor = extract::by_slug("known-hosts").expect("known_hosts extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 2);
    let rendered = hashes
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
    assert_eq!(
        rendered,
        std::fs::read_to_string(fixture("known_hosts.hash"))
            .unwrap()
            .lines()
            .collect::<Vec<_>>()
    );
    assert!(hashes[0].modes().contains(&Mode::John("known_hosts")));
    assert!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap()
            .starts_with("$known_hosts$|1|")
    );
}

#[test]
fn known_hosts_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("known_hosts"))
        .args(["--tool", "john"])
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("known_hosts"))
        .args(["--tool", "john", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["results"].as_array().unwrap().len(), 2);
    assert_eq!(value["results"][0]["type"], "known-hosts");
}

#[test]
fn known_hosts_skips_malformed_entries_and_rejects_plain_files() {
    let extractor = extract::by_slug("known-hosts").expect("known_hosts extractor");
    let mixed = "|1|not-base64|I9L3FH6RGefWIFb0Po74BVN3Fto= host\n|1|AAECAwQFBgcICQoLDA0ODxAREhM=|FBUWFxgZGhscHR4fICEiIyQlJic= ok\n";
    let hashes = extractor
        .extract(&Artifact::from_bytes("mixed", mixed.as_bytes().to_vec()))
        .expect("extract valid entry");
    assert_eq!(hashes.len(), 1);

    let plain = extract_error(extractor.extract(&Artifact::from_bytes(
        "plain",
        b"host ssh-rsa AAAA\n".to_vec(),
    )));
    assert!(plain.to_string().contains("no hashed known_hosts entries"));
}
