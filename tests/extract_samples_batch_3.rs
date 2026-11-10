//! POP3 APOP and Oracle O5LOGON sample extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::types::{O5logon, Pop3Apop};
use omniex::{HashType, RenderOptions, Tool};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_file(&fixture(kind, name)).expect("open artifact")
}

fn expected(kind: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(kind, name))
        .expect("read expected hashes")
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn extracted(kind: &str, name: &str, tool: Tool) -> Vec<String> {
    let slug = match kind {
        "pop3-apop" => Pop3Apop::SLUG,
        "o5logon" => O5logon::SLUG,
        other => panic!("unknown fixture kind {other}"),
    };
    extract::by_slug(slug)
        .expect("extractor is registered")
        .extract(&artifact(kind, name))
        .expect("extract")
        .iter()
        .map(|hash| {
            hash.render(&RenderOptions {
                tool,
                ..RenderOptions::default()
            })
            .expect("render")
        })
        .collect()
}

fn probe(kind: &str, name: &str) -> Probe {
    let slug = match kind {
        "pop3-apop" => Pop3Apop::SLUG,
        "o5logon" => O5logon::SLUG,
        other => panic!("unknown fixture kind {other}"),
    };
    extract::by_slug(slug)
        .expect("extractor")
        .probe(&artifact(kind, name))
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn apop_extracts_the_john_sample_exchange() {
    assert_eq!(
        extracted("pop3-apop", "sample.pcap", Tool::Hashcat),
        expected("pop3-apop", "sample.txt")
    );
}

#[test]
fn apop_scans_every_connection() {
    assert_eq!(
        extracted("pop3-apop", "multi.pcap", Tool::Hashcat),
        vec![
            "$apop$<1234.1111111111@server.example>$11111111111111111111111111111111",
            "$apop$<5678.2222222222@server.example>$22222222222222222222222222222222",
        ]
    );
}

#[test]
fn apop_probe_requires_a_challenge_and_response() {
    assert!(matches!(
        probe("pop3-apop", "sample.pcap"),
        Probe::Yes(reason) if reason.contains("APOP")
    ));
    assert!(matches!(
        probe("pop3-apop", "multi.pcap"),
        Probe::Yes(reason) if reason.contains("APOP")
    ));
    assert_eq!(
        extract::by_slug("pop3-apop")
            .unwrap()
            .probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extract::by_slug("pop3-apop")
            .unwrap()
            .probe(&Artifact::from_bytes("text", b"not a capture".to_vec())),
        Probe::No
    );
}

#[test]
fn apop_rejects_a_capture_without_an_exchange() {
    let data = std::fs::read(fixture("pop3-apop", "multi.pcap")).unwrap();
    let truncated = Artifact::from_bytes("truncated.pcap", data[..data.len() - 8].to_vec());
    let extractor = extract::by_slug("pop3-apop").unwrap();
    assert!(matches!(
        extractor.probe(&truncated),
        Probe::Maybe(_) | Probe::No
    ));
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn o5logon_extracts_the_four_field_serialization() {
    assert_eq!(
        extracted("o5logon", "oracle-good.pcap", Tool::John),
        expected("o5logon", "oracle-good.hash")
    );
}

#[test]
fn o5logon_extracts_the_two_field_serialization() {
    assert_eq!(
        extracted("o5logon", "legacy.pcap", Tool::John),
        expected("o5logon", "legacy.hash")
    );
}

#[test]
fn o5logon_extracts_every_session() {
    assert_eq!(
        extracted("o5logon", "multi.pcap", Tool::John),
        expected("o5logon", "multi.hash")
    );
}

#[test]
fn o5logon_probe_requires_tns_authentication_fields() {
    assert!(matches!(
        probe("o5logon", "oracle-good.pcap"),
        Probe::Yes(reason) if reason.contains("O5LOGON")
    ));
    assert!(matches!(
        probe("o5logon", "legacy.pcap"),
        Probe::Yes(reason) if reason.contains("O5LOGON")
    ));
    assert!(matches!(
        probe("o5logon", "multi.pcap"),
        Probe::Yes(reason) if reason.contains("O5LOGON")
    ));
    assert_eq!(
        extract::by_slug("o5logon")
            .unwrap()
            .probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extract::by_slug("o5logon")
            .unwrap()
            .probe(&Artifact::from_bytes("text", b"not a capture".to_vec())),
        Probe::No
    );
    assert_eq!(probe("o5logon", "text.txt"), Probe::No);
}

#[test]
fn o5logon_rejects_a_truncated_capture() {
    let data = std::fs::read(fixture("o5logon", "oracle-good.pcap")).unwrap();
    let truncated = Artifact::from_bytes("truncated.pcap", data[..data.len() - 8].to_vec());
    let extractor = extract::by_slug("o5logon").unwrap();
    assert!(matches!(
        extractor.probe(&truncated),
        Probe::Maybe(_) | Probe::No
    ));
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn cli_auto_detects_both_formats() {
    for (kind, name, slug) in [
        ("pop3-apop", "sample.pcap", Pop3Apop::SLUG),
        ("o5logon", "oracle-good.pcap", O5logon::SLUG),
    ] {
        let auto = omniex()
            .arg("extract")
            .arg("--format")
            .arg(if slug == O5logon::SLUG {
                "john"
            } else {
                "hashcat"
            })
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(
            auto.status.success(),
            "{kind}/{name}: {}",
            String::from_utf8_lossy(&auto.stderr)
        );

        let typed = omniex()
            .arg("extract")
            .arg("--type")
            .arg(slug)
            .arg("--format")
            .arg(if slug == O5logon::SLUG {
                "john"
            } else {
                "hashcat"
            })
            .arg(fixture(kind, name))
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            typed.status.success(),
            "{kind}/{name}: {}",
            String::from_utf8_lossy(&typed.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&typed.stdout).unwrap();
        assert_eq!(value[0]["type"], slug);
    }
}

#[test]
fn cli_rejects_the_wrong_type() {
    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg(Pop3Apop::SLUG)
        .arg(fixture("o5logon", "oracle-good.pcap"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());

    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg(O5logon::SLUG)
        .arg(fixture("pop3-apop", "sample.pcap"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());
}
