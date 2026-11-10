//! Java KeyStore and STRIP sample extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

const KEYSTORE_FILES: [(&str, &str); 2] = [
    ("keystore-12345678.jks", "keystore-12345678.hash"),
    ("keystore-password123.jks", "keystore-password123.hash"),
];

const STRIP_FILES: [(&str, &str); 2] = [
    ("strip.db", "strip.hash"),
    ("strip-v2.1-openwall_123.db", "strip-v2.1-openwall_123.hash"),
];

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(kind, name)).expect("read artifact"),
    )
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .expect("read expected hash")
        .trim_end()
        .to_owned()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn john(value: &dyn omniex::HashValue) -> String {
    value
        .render(&RenderOptions {
            tool: Tool::John,
            ..RenderOptions::default()
        })
        .unwrap()
}

fn probe(slug: &str, artifact: &Artifact) -> Probe {
    extract::by_slug(slug).expect("extractor").probe(artifact)
}

#[test]
fn keystore_probe_requires_a_complete_jks_container() {
    for (name, _) in KEYSTORE_FILES {
        assert!(
            matches!(
                probe("keystore", &artifact("keystore", name)),
                Probe::Yes(reason) if reason == "JKS keystore container structure"
            ),
            "{name}"
        );
    }

    assert_eq!(
        probe("keystore", &Artifact::from_bytes("empty.jks", Vec::new())),
        Probe::No
    );
    assert_eq!(
        probe("keystore", &Artifact::from_bytes("short.jks", vec![0; 11])),
        Probe::No
    );
    assert!(matches!(
        probe(
            "keystore",
            &Artifact::from_bytes("store.jceks", [0xce, 0xce, 0xce, 0xce].to_vec())
        ),
        Probe::Maybe(reason) if reason.contains("JCEKS")
    ));
    assert!(matches!(
        probe(
            "keystore",
            &Artifact::from_bytes(
                "unsupported.jks",
                [0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 3, 0, 0, 0, 0].to_vec()
            )
        ),
        Probe::No
    ));

    let bytes = std::fs::read(fixture("keystore", "keystore-12345678.jks")).unwrap();
    let truncated = Artifact::from_bytes("truncated.jks", bytes[..40].to_vec());
    assert_eq!(
        extract::by_slug("keystore").unwrap().probe(&truncated),
        Probe::No
    );
    assert!(
        extract::by_slug("keystore")
            .unwrap()
            .extract(&truncated)
            .is_err()
    );
}

#[test]
fn keystore_extracts_the_container_password() {
    for (name, expected_file) in KEYSTORE_FILES {
        let hashes = extract::by_slug("keystore")
            .unwrap()
            .extract(&artifact("keystore", name))
            .expect("extract keystore");
        assert_eq!(hashes.len(), 1, "{name}");
        assert_eq!(
            john(hashes[0].as_ref()),
            expected("keystore", expected_file),
            "{name}"
        );
        assert!(hashes[0].modes().contains(&Mode::John("keystore")));
    }
}

#[test]
fn keystore_is_ambiguous_with_private_key_extraction() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("keystore", "keystore-12345678.jks"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("ambiguous artifact"));

    let explicit = omniex()
        .args(["extract", "--type", "keystore", "--format", "john"])
        .arg(fixture("keystore", "keystore-12345678.jks"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8_lossy(&explicit.stdout).trim_end(),
        expected("keystore", "keystore-12345678.hash")
    );
}

#[test]
fn keystore_rejects_wrong_types() {
    assert!(
        extract::by_slug("keystore")
            .unwrap()
            .extract(&Artifact::from_bytes("strip.db", vec![0; 2048]))
            .is_err()
    );
    let wrong = omniex()
        .args(["extract", "--type", "keystore"])
        .arg(fixture("strip", "strip.db"))
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
}

#[test]
fn strip_probe_is_explicit_and_rejects_short_input() {
    let extractor = extract::by_slug("strip").expect("STRIP extractor");
    assert!(!extractor.exact());
    for (name, _) in STRIP_FILES {
        assert!(
            matches!(
                probe("strip", &artifact("strip", name)),
                Probe::Maybe(reason) if reason.contains("no reliable signature")
            ),
            "{name}"
        );
    }

    assert_eq!(
        probe("strip", &Artifact::from_bytes("empty.db", Vec::new())),
        Probe::No
    );
    assert_eq!(
        probe("strip", &Artifact::from_bytes("short.db", vec![0; 1023])),
        Probe::No
    );
    assert_eq!(
        probe("strip", &Artifact::from_bytes("odd.db", vec![0; 1537])),
        Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short.db", vec![0; 1023]))
            .is_err()
    );
}

#[test]
fn strip_extracts_the_first_page() {
    for (name, expected_file) in STRIP_FILES {
        let hashes = extract::by_slug("strip")
            .unwrap()
            .extract(&artifact("strip", name))
            .expect("extract STRIP");
        assert_eq!(hashes.len(), 1, "{name}");
        let rendered = john(hashes[0].as_ref());
        assert_eq!(rendered, expected("strip", expected_file), "{name}");
        assert_eq!(rendered.len(), 2056, "{name}");
        assert!(hashes[0].modes().contains(&Mode::John("STRIP")));
    }
}

#[test]
fn strip_requires_an_explicit_type() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("strip", "strip.db"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("has no reliable signature"));

    let explicit = omniex()
        .args(["extract", "--type", "strip", "--format", "john"])
        .arg(fixture("strip", "strip.db"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8_lossy(&explicit.stdout).trim_end(),
        expected("strip", "strip.hash")
    );

    let wrong = omniex()
        .args(["extract", "--type", "strip"])
        .arg(fixture("keystore", "keystore-12345678.jks"))
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
}
