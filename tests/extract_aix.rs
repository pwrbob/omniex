//! AIX, RACF, and Lotus Notes 5 extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

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
fn aix_extractors_select_their_scheme() {
    for slug in ["aix-smd5", "ssha1-aix", "ssha256-aix", "ssha512-aix"] {
        let extractor = extract::by_slug(slug).expect("AIX extractor");
        assert!(matches!(
            extractor.probe(&artifact("aix", "passwd")),
            Probe::Yes(_)
        ));
        let hashes = extractor
            .extract(&artifact("aix", "passwd"))
            .expect("extract");
        assert_eq!(
            hashes[0].render(&RenderOptions::default()).unwrap(),
            std::fs::read_to_string(fixture("aix", &format!("{slug}.hash")))
                .unwrap()
                .trim_end()
        );
    }
}

#[test]
fn racf_extracts_cracf_records() {
    let extractor = extract::by_slug("racf").expect("RACF extractor");
    assert!(matches!(
        extractor.probe(&artifact("racf", "CRACF.TXT")),
        Probe::Yes(reason) if reason == "RACF CRACF record"
    ));
    let hashes = extractor
        .extract(&artifact("racf", "CRACF.TXT"))
        .expect("extract");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("racf", "CRACF.hash"))
            .unwrap()
            .trim_end()
    );
}

#[test]
fn lotus5_extracts_a_16_byte_user_blob() {
    let extractor = extract::by_slug("lotus5").expect("Lotus 5 extractor");
    assert!(matches!(
        extractor.probe(&artifact("lotus5", "user.id")),
        Probe::Yes(reason) if reason == "Lotus Notes 5 user ID blob"
    ));
    let hashes = extractor
        .extract(&artifact("lotus5", "user.id"))
        .expect("extract");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("lotus5", "user.id.hash"))
            .unwrap()
            .trim_end()
    );
}

#[test]
fn new_extractors_auto_detect_in_the_cli() {
    for (kind, name, slug) in [
        ("aix", "passwd", "aix-smd5"),
        ("racf", "CRACF.TXT", "racf"),
        ("lotus5", "user.id", "lotus5"),
    ] {
        let output = omniex()
            .args(["extract", "--type", slug])
            .arg(fixture(kind, name))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}
