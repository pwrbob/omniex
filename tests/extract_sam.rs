//! NTLM extraction from SAM hives and plain hash lists.

use std::path::{Path, PathBuf};

use omniex::RenderOptions;
use omniex::extract::{self, Artifact, Probe};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/ntlm")
        .join(name)
}

fn artifact(name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(name)).expect("read fixture"))
}

fn expected() -> Vec<String> {
    std::fs::read_to_string(fixture("expected.hash"))
        .expect("expected hashes")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn rendered(artifact: &Artifact) -> Vec<String> {
    extract::by_slug("ntlm")
        .expect("ntlm extractor")
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect()
}

#[test]
fn sam_hive_yields_every_local_nt_hash() {
    let sam = artifact("sam.hive");
    let extractor = extract::by_slug("ntlm").expect("ntlm extractor");
    assert!(matches!(extractor.probe(&sam), Probe::Yes(_)));
    assert_eq!(rendered(&sam), expected());
}

#[test]
fn aes_sam_hive_yields_its_nt_hash() {
    let sam = artifact("sam-aes.hive");
    let extractor = extract::by_slug("ntlm").expect("ntlm extractor");
    assert!(matches!(extractor.probe(&sam), Probe::Yes(_)));
    assert_eq!(
        rendered(&sam),
        std::fs::read_to_string(fixture("expected-aes.hash"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

#[test]
fn sam_hive_rejects_truncated_and_unrelated_registry_input() {
    let extractor = extract::by_slug("ntlm").expect("ntlm extractor");
    for name in ["truncated.hive", "unrelated.hive"] {
        let input = artifact(name);
        assert_eq!(extractor.probe(&input), Probe::No, "{name}");
        assert!(extractor.extract(&input).is_err(), "{name}");
    }
}

#[test]
fn hash_list_path_still_works_for_ntlm() {
    let hashes = Artifact::from_bytes(
        "hashes.txt",
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/artifacts/hashlist/hashes.txt"),
        )
        .unwrap(),
    );
    let extractor = extract::by_slug("ntlm").expect("ntlm extractor");
    assert!(matches!(extractor.probe(&hashes), Probe::Maybe(_)));

    let expected: Vec<String> = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/artifacts/hashlist/ntlm.hash"),
    )
    .unwrap()
    .lines()
    .map(str::to_owned)
    .collect();
    assert_eq!(rendered(&hashes), expected);
}

#[test]
fn exactly_one_extractor_is_registered_for_ntlm() {
    assert_eq!(
        extract::EXTRACTORS
            .iter()
            .filter(|extractor| extractor.slug() == "ntlm")
            .count(),
        1
    );
}
