//! Legacy password hashes embedded in text dumps.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

const CASES: &[(&str, Tool)] = &[
    ("as400-des", Tool::Hashcat),
    ("as400-ssha1", Tool::Hashcat),
    ("lotus-notes", Tool::Hashcat),
    ("openvms", Tool::John),
    ("oracle11", Tool::John),
    ("oracle12c", Tool::John),
    ("oracle-otm", Tool::Hashcat),
    ("racf-kdfaes", Tool::Hashcat),
    ("racf-passphrase", Tool::Hashcat),
    ("sybase-prop", Tool::John),
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/hashdump")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("dump.txt", std::fs::read(fixture("dump.txt")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn dump_extractors_find_their_hash_formats() {
    for (slug, tool) in CASES {
        let extractor = extract::by_slug(slug).expect("dump extractor");
        assert!(
            matches!(extractor.probe(&artifact()), Probe::Yes(_)),
            "{slug}"
        );
        let hashes = extractor.extract(&artifact()).expect("extract");
        assert_eq!(hashes.len(), 1, "{slug}");
        assert_eq!(
            hashes[0]
                .render(&RenderOptions {
                    tool: *tool,
                    ..RenderOptions::default()
                })
                .unwrap(),
            std::fs::read_to_string(fixture(&format!("{slug}.hash")))
                .unwrap()
                .trim_end(),
            "{slug}"
        );
    }
}

#[test]
fn dump_is_ambiguous_and_requires_type() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("dump.txt"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous artifact"));

    for (slug, format) in [
        ("oracle11", "john"),
        ("as400-des", "hashcat"),
        ("sybase-prop", "john"),
    ] {
        let output = omniex()
            .args(["extract", "--type", slug, "--tool", format])
            .arg(fixture("dump.txt"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}

#[test]
fn dump_extractors_reject_unrelated_text() {
    let plain = Artifact::from_bytes("plain.txt", b"hello world\n".to_vec());
    for (slug, _) in CASES {
        let extractor = extract::by_slug(slug).expect("dump extractor");
        assert_eq!(extractor.probe(&plain), Probe::No, "{slug}");
    }
}
