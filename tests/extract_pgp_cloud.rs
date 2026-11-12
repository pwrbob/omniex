//! PGP WDE, PGP Disk, and 1Password cloudkeychain extraction.

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

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pgpwde_probe_and_extract() {
    let extractor = extract::by_slug("pgpwde").expect("PGP WDE extractor");
    assert!(matches!(
        extractor.probe(&artifact("pgpwde", "sample.img")),
        Probe::Yes(reason) if reason == "PGP WDE user record"
    ));
    let hashes = extractor
        .extract(&artifact("pgpwde", "sample.img"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("pgpwde", "sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("pgpwde")));
}

#[test]
fn pgpdisk_probe_and_extract() {
    let extractor = extract::by_slug("pgpdisk").expect("PGP Disk extractor");
    assert!(matches!(
        extractor.probe(&artifact("pgpdisk", "sample.pgd")),
        Probe::Yes(reason) if reason == "PGP Virtual Disk main header"
    ));
    let hashes = extractor
        .extract(&artifact("pgpdisk", "sample.pgd"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("pgpdisk", "sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("pgpdisk")));
}

#[test]
fn cloudkeychain_probe_and_extract() {
    let extractor = extract::by_slug("cloudkeychain").expect("cloudkeychain extractor");
    assert!(matches!(
        extractor.probe(&artifact("cloudkeychain", "default/profile.js")),
        Probe::Yes(reason) if reason == "1Password cloudkeychain profile"
    ));
    let hashes = extractor
        .extract(&artifact("cloudkeychain", "default/profile.js"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("cloudkeychain", "sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("cloudkeychain")));
}

#[test]
fn new_extractors_auto_detect_or_require_type() {
    for (kind, name, slug) in [
        ("pgpwde", "sample.img", "pgpwde"),
        ("pgpdisk", "sample.pgd", "pgpdisk"),
        ("cloudkeychain", "default/profile.js", "cloudkeychain"),
    ] {
        let output = omniex()
            .args(["extract", "--type", slug, "--tool", "john"])
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}
