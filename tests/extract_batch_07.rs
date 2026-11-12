//! Kerberos TGS-REP AES and AS-REQ pre-authentication extraction.

use std::collections::BTreeSet;
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

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn hashes(slug: &str, artifact: &Artifact) -> Vec<String> {
    let extractor = extract::by_slug(slug).expect("extractor");
    extractor
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|value| value.render(&RenderOptions::default()).unwrap())
        .collect()
}

fn probe(slug: &str, artifact: &Artifact) -> Probe {
    extract::by_slug(slug).expect("extractor").probe(artifact)
}

#[test]
fn probes_require_structural_evidence() {
    for (slug, kind, name) in [
        ("krb5tgs17", "krb5tgs17", "tgsrep.der"),
        ("krb5tgs17", "krb5tgs17", "tgsrep.pcap"),
        ("krb5tgs18", "krb5tgs18", "tgsrep.der"),
        ("krb5tgs18", "krb5tgs18", "tgsrep.pcap"),
        ("krb5pa23", "krb5pa23", "asreq.der"),
        ("krb5pa23", "krb5pa23", "asreq.pcap"),
        ("krb5pa17", "krb5pa17", "asreq.der"),
        ("krb5pa17", "krb5pa17", "asreq-wrapped.der"),
        ("krb5pa17", "krb5pa17", "asreq.pcap"),
        ("krb5pa18", "krb5pa18", "asreq.der"),
        ("krb5pa18", "krb5pa18", "asreq.pcap"),
    ] {
        assert!(
            matches!(probe(slug, &artifact(kind, name)), Probe::Yes(_)),
            "{slug} {name}"
        );
    }

    for (slug, kind, name) in [
        ("krb5tgs17", "krb5tgs18", "tgsrep.der"),
        ("krb5tgs18", "krb5tgs17", "tgsrep.der"),
        ("krb5tgs17", "krb5pa23", "asreq.der"),
        ("krb5pa23", "krb5tgs17", "tgsrep.der"),
        ("krb5pa17", "krb5pa18", "asreq.der"),
        ("krb5pa18", "krb5pa17", "asreq.der"),
        ("krb5pa23", "krb5pa17", "asreq.der"),
    ] {
        assert_eq!(
            probe(slug, &artifact(kind, name)),
            Probe::No,
            "{slug} {name}"
        );
    }

    let text = Artifact::from_bytes("note.txt", b"not a capture".to_vec());
    let empty = Artifact::from_bytes("empty", Vec::new());
    for slug in ["krb5tgs17", "krb5tgs18", "krb5pa23", "krb5pa17", "krb5pa18"] {
        assert_eq!(probe(slug, &text), Probe::No, "{slug}");
        assert_eq!(probe(slug, &empty), Probe::No, "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&text).is_err());
        assert!(extract::by_slug(slug).unwrap().extract(&empty).is_err());
    }
}

#[test]
fn truncated_captures_probe_maybe_and_fail_to_extract() {
    for (slug, kind, name) in [
        ("krb5tgs17", "krb5tgs17", "tgsrep.pcap"),
        ("krb5tgs18", "krb5tgs18", "tgsrep.pcap"),
        ("krb5pa23", "krb5pa23", "asreq.pcap"),
        ("krb5pa17", "krb5pa17", "asreq.pcap"),
        ("krb5pa18", "krb5pa18", "asreq.pcap"),
    ] {
        let data = std::fs::read(fixture(kind, name)).unwrap();
        let truncated = Artifact::from_bytes("truncated.pcap", data[..30].to_vec());
        assert!(matches!(probe(slug, &truncated), Probe::Maybe(_)), "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&truncated).is_err());

        let der = std::fs::read(fixture(kind, &name.replace(".pcap", ".der"))).unwrap();
        let cut = Artifact::from_bytes("truncated.der", der[..der.len() / 2].to_vec());
        assert!(extract::by_slug(slug).unwrap().extract(&cut).is_err());
    }
}

#[test]
fn extractors_match_their_fixtures() {
    for (slug, kind, name, hash, mode) in [
        ("krb5tgs17", "krb5tgs17", "tgsrep.der", "tgsrep.hash", 19600),
        (
            "krb5tgs17",
            "krb5tgs17",
            "tgsrep.pcap",
            "tgsrep.hash",
            19600,
        ),
        ("krb5tgs18", "krb5tgs18", "tgsrep.der", "tgsrep.hash", 19700),
        (
            "krb5tgs18",
            "krb5tgs18",
            "tgsrep.pcap",
            "tgsrep.hash",
            19700,
        ),
        ("krb5pa23", "krb5pa23", "asreq.der", "asreq.hash", 7500),
        ("krb5pa23", "krb5pa23", "asreq.pcap", "asreq.hash", 7500),
        ("krb5pa17", "krb5pa17", "asreq.der", "asreq.hash", 19800),
        (
            "krb5pa17",
            "krb5pa17",
            "asreq-wrapped.der",
            "asreq.hash",
            19800,
        ),
        ("krb5pa17", "krb5pa17", "asreq.pcap", "asreq.hash", 19800),
        ("krb5pa18", "krb5pa18", "asreq.der", "asreq.hash", 19900),
        ("krb5pa18", "krb5pa18", "asreq.pcap", "asreq.hash", 19900),
    ] {
        assert_eq!(
            hashes(slug, &artifact(kind, name)),
            vec![expected(kind, hash)],
            "{slug} {name}"
        );
        let values = extract::by_slug(slug)
            .unwrap()
            .extract(&artifact(kind, name))
            .unwrap();
        assert!(values[0].modes().contains(&Mode::Hashcat(mode)), "{slug}");
    }
}

#[test]
fn extracted_kerberos_preauth_renders_for_john() {
    for (slug, kind, name, expected) in [
        (
            "krb5pa23",
            "krb5pa23",
            "asreq.der",
            "$krb5pa$23$alice$EXAMPLE.COM$$101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233000102030405060708090a0b0c0d0e0f",
        ),
        (
            "krb5pa17",
            "krb5pa17",
            "asreq.der",
            "$krb5pa$17$carol$EXAMPLE.COM$$808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
        ),
    ] {
        let artifact = artifact(kind, name);
        let values = extract::by_slug(slug).unwrap().extract(&artifact).unwrap();
        assert!(values[0].modes().contains(&Mode::John(match slug {
            "krb5pa23" => "krb5pa-md5",
            _ => "krb5pa-sha1",
        })));
        let rendered = values[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap();
        assert_eq!(rendered, expected, "{slug}");

        let output = omniex()
            .arg("extract")
            .arg("--type")
            .arg(slug)
            .arg("--tool")
            .arg("john")
            .args(["--format", "json"])
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value[0]["hash"], expected, "{slug}");
    }
}

#[test]
fn pa23_scans_every_message_in_a_capture() {
    let values: BTreeSet<String> = hashes("krb5pa23", &artifact("krb5pa23", "multi.pcap"))
        .into_iter()
        .collect();
    let wanted: BTreeSet<String> = [
        expected("krb5pa23", "asreq.hash"),
        expected("krb5pa23", "multi.hash"),
    ]
    .into_iter()
    .collect();
    assert_eq!(values, wanted);
}

#[test]
fn extractors_reject_the_wrong_message_shape() {
    for (slug, kind, name) in [
        ("krb5tgs17", "krb5tgs18", "tgsrep.der"),
        ("krb5tgs18", "krb5tgs17", "tgsrep.der"),
        ("krb5tgs17", "krb5pa23", "asreq.der"),
        ("krb5pa23", "krb5tgs17", "tgsrep.der"),
        ("krb5pa17", "krb5pa18", "asreq.der"),
        ("krb5pa18", "krb5pa17", "asreq.der"),
        ("krb5pa23", "krb5pa17", "asreq.der"),
    ] {
        assert!(
            extract::by_slug(slug)
                .unwrap()
                .extract(&artifact(kind, name))
                .is_err(),
            "{slug} must reject {kind}/{name}"
        );
    }
}

#[test]
fn cli_auto_detects_and_accepts_explicit_types() {
    for (kind, name, slug) in [
        ("krb5tgs17", "tgsrep.der", "krb5tgs17"),
        ("krb5tgs18", "tgsrep.der", "krb5tgs18"),
        ("krb5pa23", "asreq.der", "krb5pa23"),
        ("krb5pa17", "asreq.der", "krb5pa17"),
        ("krb5pa18", "asreq.der", "krb5pa18"),
    ] {
        let auto = omniex()
            .arg("extract")
            .args(["--format", "json"])
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(auto.status.success(), "{slug}");
        let value: serde_json::Value = serde_json::from_slice(&auto.stdout).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1, "{slug}");
        assert_eq!(value[0]["type"], slug);

        let explicit = omniex()
            .arg("extract")
            .arg("--type")
            .arg(slug)
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(explicit.status.success(), "{slug}");
    }

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .args(["--format", "json"])
        .arg(fixture("krb5pa23", "multi.pcap"))
        .output()
        .unwrap();
    assert!(all.status.success());
    let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);

    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg("krb5pa17")
        .arg(fixture("krb5pa18", "asreq.der"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());
}
