//! Oubliette database extraction.

use std::path::{Path, PathBuf};

use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/oubliette")
        .join(name)
}

fn artifact(name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(name)).unwrap())
}

#[test]
fn oubliette_extracts_the_header_digest() {
    for (slug, name, prefix) in [
        ("oubliette-blowfish", "blowfish.oub", "$oubliette-blowfish$"),
        ("oubliette-idea", "idea.oub", "$oubliette-idea$"),
    ] {
        let extractor = extract::by_slug(slug).expect("extractor");
        assert!(matches!(extractor.probe(&artifact(name)), Probe::Yes(_)));
        let values = extractor.extract(&artifact(name)).expect("extract");
        assert_eq!(
            values[0]
                .render(&RenderOptions {
                    tool: Tool::John,
                    ..RenderOptions::default()
                })
                .unwrap(),
            format!(
                "{prefix}{}",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
        );
    }
}

#[test]
fn oubliette_rejects_the_wrong_algorithm_and_short_input() {
    assert!(
        extract::by_slug("oubliette-blowfish")
            .unwrap()
            .extract(&artifact("idea.oub"))
            .is_err()
    );
    assert!(
        extract::by_slug("oubliette-idea")
            .unwrap()
            .extract(&artifact("blowfish.oub"))
            .is_err()
    );
    assert!(
        extract::by_slug("oubliette-idea")
            .unwrap()
            .extract(&Artifact::from_bytes("short", vec![0; 8]))
            .is_err()
    );
}
