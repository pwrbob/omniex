//! Plain hash-list extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

const SLUGS: &[&str] = &[
    "md5",
    "md4",
    "ntlm",
    "lm",
    "sha1",
    "ripemd",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "gost",
    "keccak",
    "md2",
    "sha0",
    "sha3",
    "sm3",
    "streebog",
    "tiger",
    "whirlpool",
    "skein-512",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/hashlist")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("hashes.txt", std::fs::read(fixture("hashes.txt")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn hash_list_extractors_select_their_digest_sizes() {
    for slug in SLUGS {
        let extractor = extract::by_slug(slug).expect("hash-list extractor");
        assert!(
            matches!(extractor.probe(&artifact()), Probe::Maybe(_)),
            "{slug}"
        );
        let hashes = extractor.extract(&artifact()).expect("extract");
        assert_eq!(
            hashes
                .iter()
                .map(|value| value.render(&RenderOptions::default()).unwrap())
                .collect::<Vec<_>>(),
            std::fs::read_to_string(fixture(&format!("{slug}.hash")))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            "{slug}"
        );
    }
}

#[test]
fn hash_list_is_ambiguous_and_requires_type() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("hashes.txt"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"));

    for slug in ["md5", "sha256", "lm"] {
        let output = omniex()
            .args(["extract", "--type", slug])
            .arg(fixture("hashes.txt"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}

#[test]
fn hash_list_ignores_comments_and_blank_lines() {
    let extractor = extract::by_slug("sha256").expect("sha256 extractor");
    let input = Artifact::from_bytes(
        "hashes.txt",
        b"# comment\n\nuser:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
            .to_vec(),
    );
    assert_eq!(extractor.extract(&input).unwrap().len(), 1);
}
