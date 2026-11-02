//! Extraction for Windows hive records, BitLocker metadata, and Veeam backups.

use std::path::{Path, PathBuf};

use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(slug, name)).expect("read fixture"),
    )
}

fn expected(slug: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(slug, "expected.hash"))
        .expect("expected hash")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn windows_artifacts_render_their_records() {
    for (slug, name) in [
        ("dcc2", "dump.txt"),
        ("dpapi", "dump.txt"),
        ("veeam", "sample.vbk"),
        ("windows-hello", "dump.txt"),
        ("bitlocker", "sample.img"),
    ] {
        let extractor = extract::by_slug(slug).expect("registered extractor");
        assert!(
            matches!(extractor.probe(&artifact(slug, name)), Probe::Yes(_)),
            "{slug}"
        );
        let rendered: Vec<String> = extractor
            .extract(&artifact(slug, name))
            .expect("extract")
            .iter()
            .map(|hash| hash.render(&RenderOptions::default()).unwrap())
            .collect();
        assert_eq!(rendered, expected(slug), "{slug}");
    }
}

#[test]
fn windows_extractors_reject_unrelated_input() {
    for slug in ["dcc2", "dpapi", "veeam", "windows-hello", "bitlocker"] {
        let extractor = extract::by_slug(slug).expect("registered extractor");
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("plain", b"not a hive".to_vec())),
            Probe::No,
            "{slug}"
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes("plain", b"not a hive".to_vec()))
                .is_err(),
            "{slug}"
        );
    }
}
