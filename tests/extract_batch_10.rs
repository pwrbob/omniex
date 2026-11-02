//! WPA and Kerberos network-capture extraction.

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
        .map(|value| {
            value
                .render(&RenderOptions::default())
                .or_else(|_| {
                    value.render(&RenderOptions {
                        tool: Tool::John,
                        ..RenderOptions::default()
                    })
                })
                .unwrap()
        })
        .collect()
}

fn probe(slug: &str, artifact: &Artifact) -> Probe {
    extract::by_slug(slug).expect("extractor").probe(artifact)
}

#[test]
fn network_probes_require_structural_evidence() {
    for (slug, kind, name) in [
        ("wpa-pmkid", "wpa-pmkid", "eapol.pcap"),
        ("wpa-pmkid", "wpa-pmkid", "pmkid.pcap"),
        ("wpa-pmkid-legacy", "wpa-pmkid-legacy", "pmkid.pcap"),
        ("krb5asrep23", "krb5asrep23", "asrep.pcap"),
        ("krb5asrep23", "krb5asrep23", "asrep.der"),
        ("krb5asrep23", "krb5asrep23", "asrep.pcapng"),
        ("wpa-pmkid", "wpa-pmkid", "eapol.pcapng"),
        ("krb5asrep-aes", "krb5asrep-aes", "asrep.pcap"),
        ("krb5asrep-aes", "krb5asrep-aes", "asrep18.der"),
        ("krb5tgs23", "krb5tgs23", "tgsrep.pcap"),
    ] {
        assert!(
            matches!(probe(slug, &artifact(kind, name)), Probe::Yes(_)),
            "{slug} {name}"
        );
    }

    for (slug, kind, name) in [
        ("wpa-pmkid", "krb5asrep23", "asrep.pcap"),
        ("wpa-pmkid-legacy", "wpa-pmkid", "eapol.pcap"),
        ("krb5asrep23", "krb5tgs23", "tgsrep.pcap"),
        ("krb5asrep23", "krb5asrep-aes", "asrep.pcap"),
        ("krb5tgs23", "krb5asrep23", "asrep.pcap"),
        ("krb5asrep-aes", "krb5asrep23", "asrep.pcap"),
    ] {
        assert_eq!(
            probe(slug, &artifact(kind, name)),
            Probe::No,
            "{slug} {name}"
        );
    }

    let text = Artifact::from_bytes("note.txt", b"not a capture".to_vec());
    for slug in [
        "wpa-pmkid",
        "wpa-pmkid-legacy",
        "krb5asrep23",
        "krb5asrep-aes",
        "krb5tgs23",
    ] {
        assert_eq!(probe(slug, &text), Probe::No, "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&text).is_err());
    }
}

#[test]
fn truncated_captures_probe_maybe_and_fail_to_extract() {
    let bytes = std::fs::read(fixture("wpa-pmkid", "eapol.pcap")).unwrap();
    let truncated = Artifact::from_bytes("truncated.pcap", bytes[..30].to_vec());
    for slug in ["wpa-pmkid", "wpa-pmkid-legacy"] {
        assert!(matches!(probe(slug, &truncated), Probe::Maybe(_)), "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&truncated).is_err());
    }

    let bytes = std::fs::read(fixture("krb5asrep23", "asrep.pcap")).unwrap();
    let truncated = Artifact::from_bytes("truncated.pcap", bytes[..30].to_vec());
    for slug in ["krb5asrep23", "krb5asrep-aes", "krb5tgs23"] {
        assert!(matches!(probe(slug, &truncated), Probe::Maybe(_)), "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&truncated).is_err());
    }
}

#[test]
fn empty_input_is_never_recognized() {
    let empty = Artifact::from_bytes("empty", Vec::new());
    for slug in [
        "wpa-pmkid",
        "wpa-pmkid-legacy",
        "krb5asrep23",
        "krb5asrep-aes",
        "krb5tgs23",
    ] {
        assert_eq!(probe(slug, &empty), Probe::No, "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&empty).is_err());
    }
}

#[test]
fn wpa_extractors_match_their_fixtures() {
    for (name, kinds) in [
        ("eapol.pcap", vec!["eapol.hash"]),
        ("pmkid.pcap", vec!["pmkid.hash"]),
    ] {
        let values = hashes("wpa-pmkid", &artifact("wpa-pmkid", name));
        let expected: Vec<String> = kinds
            .iter()
            .map(|hash| expected("wpa-pmkid", hash))
            .collect();
        assert_eq!(values, expected, "{name}");
    }

    let legacy = hashes(
        "wpa-pmkid-legacy",
        &artifact("wpa-pmkid-legacy", "pmkid.pcap"),
    );
    assert_eq!(legacy, vec![expected("wpa-pmkid-legacy", "pmkid.hash")]);

    let extractor = extract::by_slug("wpa-pmkid").unwrap();
    let values = extractor
        .extract(&artifact("wpa-pmkid", "eapol.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::Hashcat(22000)));
    let legacy = extract::by_slug("wpa-pmkid-legacy")
        .unwrap()
        .extract(&artifact("wpa-pmkid-legacy", "pmkid.pcap"))
        .unwrap();
    assert!(legacy[0].modes().contains(&Mode::Hashcat(16800)));
}

#[test]
fn wpa_extractors_scan_every_handshake() {
    let values: BTreeSet<String> = hashes("wpa-pmkid", &artifact("wpa-pmkid", "multi.pcap"))
        .into_iter()
        .collect();
    let expected: BTreeSet<String> = [
        expected("wpa-pmkid", "eapol.hash"),
        expected("wpa-pmkid", "multi.hash"),
    ]
    .into_iter()
    .collect();
    assert_eq!(values, expected);
}

#[test]
fn kerberos_extractors_match_their_fixtures() {
    assert_eq!(
        hashes("krb5asrep23", &artifact("krb5asrep23", "asrep.pcap")),
        vec![expected("krb5asrep23", "asrep.hash")]
    );
    assert_eq!(
        hashes("krb5asrep23", &artifact("krb5asrep23", "asrep.der")),
        vec![expected("krb5asrep23", "asrep.hash")]
    );
    assert_eq!(
        hashes("krb5asrep23", &artifact("krb5asrep23", "asrep.pcapng")),
        vec![expected("krb5asrep23", "asrep.hash")]
    );
    assert_eq!(
        hashes("wpa-pmkid", &artifact("wpa-pmkid", "eapol.pcapng")),
        vec![expected("wpa-pmkid", "eapol.hash")]
    );

    let aes = hashes("krb5asrep-aes", &artifact("krb5asrep-aes", "asrep.pcap"));
    assert_eq!(aes, vec![expected("krb5asrep-aes", "asrep.hash")]);
    assert_eq!(
        hashes("krb5asrep-aes", &artifact("krb5asrep-aes", "asrep18.der")),
        vec![expected("krb5asrep-aes", "asrep18.hash")]
    );

    assert_eq!(
        hashes("krb5tgs23", &artifact("krb5tgs23", "tgsrep.pcap")),
        vec![expected("krb5tgs23", "tgsrep.hash")]
    );
    assert_eq!(
        hashes("krb5tgs23", &artifact("krb5tgs23", "tgsrep.der")),
        vec![expected("krb5tgs23", "tgsrep.hash")]
    );

    let values = extract::by_slug("krb5asrep23")
        .unwrap()
        .extract(&artifact("krb5asrep23", "asrep.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::Hashcat(18200)));
    let values = extract::by_slug("krb5tgs23")
        .unwrap()
        .extract(&artifact("krb5tgs23", "tgsrep.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::Hashcat(13100)));
}

#[test]
fn kerberos_extractors_scan_every_message() {
    let values: BTreeSet<String> = hashes("krb5asrep23", &artifact("krb5asrep23", "multi.pcap"))
        .into_iter()
        .collect();
    let wanted: BTreeSet<String> = [
        expected("krb5asrep23", "asrep.hash"),
        expected("krb5asrep23", "multi.hash"),
    ]
    .into_iter()
    .collect();
    assert_eq!(values, wanted);

    let values: BTreeSet<String> =
        hashes("krb5asrep-aes", &artifact("krb5asrep-aes", "multi.pcap"))
            .into_iter()
            .collect();
    let wanted: BTreeSet<String> = [
        expected("krb5asrep-aes", "asrep.hash"),
        expected("krb5asrep-aes", "multi.hash"),
    ]
    .into_iter()
    .collect();
    assert_eq!(values, wanted);
}

#[test]
fn extractors_reject_the_wrong_message_shape() {
    for (slug, kind, name) in [
        ("krb5asrep23", "krb5asrep-aes", "asrep.pcap"),
        ("krb5asrep-aes", "krb5asrep23", "asrep.pcap"),
        ("krb5tgs23", "krb5asrep23", "asrep.pcap"),
        ("krb5asrep23", "krb5tgs23", "tgsrep.pcap"),
        ("wpa-pmkid-legacy", "wpa-pmkid", "eapol.pcap"),
    ] {
        assert!(
            extract::by_slug(slug)
                .unwrap()
                .extract(&artifact(kind, name))
                .is_err(),
            "{slug} must reject {kind}/{name}"
        );
        assert_eq!(probe(slug, &artifact(kind, name)), Probe::No, "{slug}");
    }
}

#[test]
fn captures_auto_detect_and_accept_explicit_types() {
    let auto = omniex()
        .arg("extract")
        .arg("--json")
        .arg(fixture("wpa-pmkid", "eapol.pcap"))
        .output()
        .unwrap();
    assert!(auto.status.success());
    let value: serde_json::Value = serde_json::from_slice(&auto.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 1);
    assert_eq!(value[0]["type"], "wpa-pmkid");

    let raw = omniex()
        .arg("extract")
        .arg("--json")
        .arg(fixture("krb5asrep23", "asrep.der"))
        .output()
        .unwrap();
    assert!(raw.status.success());
    let value: serde_json::Value = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(value[0]["type"], "krb5asrep23");

    let explicit = omniex()
        .arg("extract")
        .arg("--type")
        .arg("krb5tgs23")
        .arg(fixture("krb5tgs23", "tgsrep.pcap"))
        .output()
        .unwrap();
    assert!(explicit.status.success());

    // Two extractors recognize a PMKID capture, so auto-detection is ambiguous.
    let ambiguous = omniex()
        .arg("extract")
        .arg(fixture("wpa-pmkid", "pmkid.pcap"))
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());

    let chosen = omniex()
        .arg("extract")
        .arg("--type")
        .arg("wpa-pmkid")
        .arg(fixture("wpa-pmkid", "pmkid.pcap"))
        .output()
        .unwrap();
    assert!(chosen.status.success());

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg("--json")
        .arg(fixture("wpa-pmkid", "pmkid.pcap"))
        .output()
        .unwrap();
    assert!(all.status.success());
    let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);

    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg("krb5tgs23")
        .arg(fixture("krb5asrep23", "asrep.pcap"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());
}

#[test]
fn routing_extractors_match_their_fixtures() {
    for (slug, name, hash) in [
        ("ospf-md5", "ospf.pcap", "ospf.hash"),
        ("ospf-md5", "rip.pcap", "rip.hash"),
        ("tcp-md5", "tcp.pcap", "tcp.hash"),
        ("hsrp", "hsrp.pcap", "hsrp.hash"),
        ("hsrp", "hsrp2.pcap", "hsrp2.hash"),
        ("eigrp", "eigrp.pcap", "eigrp.hash"),
        ("eigrp", "eigrp-sha256.pcap", "eigrp-sha256.hash"),
        ("sntp-ms", "sntp.pcap", "sntp.hash"),
    ] {
        assert_eq!(
            hashes(slug, &artifact(slug, name)),
            vec![expected(slug, hash)],
            "{slug}/{name}"
        );
    }
}

#[test]
fn routing_extractors_scan_every_record() {
    let values: BTreeSet<String> = hashes("ospf-md5", &artifact("ospf-md5", "multi.pcap"))
        .into_iter()
        .collect();
    let wanted: BTreeSet<String> = [
        expected("ospf-md5", "ospf.hash"),
        expected("ospf-md5", "rip.hash"),
    ]
    .into_iter()
    .collect();
    assert_eq!(values, wanted);
}

#[test]
fn routing_probes_require_structural_evidence() {
    for (slug, name) in [
        ("ospf-md5", "ospf.pcap"),
        ("ospf-md5", "rip.pcap"),
        ("tcp-md5", "tcp.pcap"),
        ("hsrp", "hsrp.pcap"),
        ("hsrp", "hsrp2.pcap"),
        ("eigrp", "eigrp.pcap"),
        ("eigrp", "eigrp-sha256.pcap"),
        ("sntp-ms", "sntp.pcap"),
    ] {
        assert!(
            matches!(probe(slug, &artifact(slug, name)), Probe::Yes(_)),
            "{slug}/{name}"
        );
    }

    for (slug, kind, name) in [
        ("ospf-md5", "tcp-md5", "tcp.pcap"),
        ("tcp-md5", "ospf-md5", "ospf.pcap"),
        ("hsrp", "eigrp", "eigrp.pcap"),
        ("eigrp", "sntp-ms", "sntp.pcap"),
        ("sntp-ms", "hsrp", "hsrp.pcap"),
    ] {
        assert_eq!(
            probe(slug, &artifact(kind, name)),
            Probe::No,
            "{slug} {kind}/{name}"
        );
        assert!(
            extract::by_slug(slug)
                .unwrap()
                .extract(&artifact(kind, name))
                .is_err()
        );
    }

    let text = Artifact::from_bytes("note.txt", b"not a capture".to_vec());
    for slug in ["ospf-md5", "tcp-md5", "hsrp", "eigrp", "sntp-ms"] {
        assert_eq!(probe(slug, &text), Probe::No, "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&text).is_err());
    }
}

#[test]
fn routing_truncated_captures_probe_maybe_and_fail_to_extract() {
    let bytes = std::fs::read(fixture("ospf-md5", "ospf.pcap")).unwrap();
    let truncated = Artifact::from_bytes("truncated.pcap", bytes[..30].to_vec());
    for slug in ["ospf-md5", "tcp-md5", "hsrp", "eigrp", "sntp-ms"] {
        assert!(matches!(probe(slug, &truncated), Probe::Maybe(_)), "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&truncated).is_err());
    }
}

#[test]
fn routing_empty_input_is_never_recognized() {
    let empty = Artifact::from_bytes("empty", Vec::new());
    for slug in ["ospf-md5", "tcp-md5", "hsrp", "eigrp", "sntp-ms"] {
        assert_eq!(probe(slug, &empty), Probe::No, "{slug}");
        assert!(extract::by_slug(slug).unwrap().extract(&empty).is_err());
    }
}

#[test]
fn routing_captures_auto_detect_and_accept_explicit_types() {
    let auto = omniex()
        .arg("extract")
        .arg("--json")
        .arg(fixture("ospf-md5", "multi.pcap"))
        .output()
        .unwrap();
    assert!(auto.status.success());
    let value: serde_json::Value = serde_json::from_slice(&auto.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 2);
    assert_eq!(value[0]["type"], "ospf-md5");

    let explicit = omniex()
        .arg("extract")
        .arg("--type")
        .arg("sntp-ms")
        .arg(fixture("sntp-ms", "sntp.pcap"))
        .output()
        .unwrap();
    assert!(explicit.status.success());

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg("--format")
        .arg("john")
        .arg("--json")
        .arg(fixture("hsrp", "hsrp2.pcap"))
        .output()
        .unwrap();
    assert!(all.status.success());
    let value: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 1);
    assert_eq!(value[0]["type"], "hsrp");

    let wrong = omniex()
        .arg("extract")
        .arg("--type")
        .arg("tcp-md5")
        .arg(fixture("ospf-md5", "ospf.pcap"))
        .output()
        .unwrap();
    assert!(!wrong.status.success());
}
