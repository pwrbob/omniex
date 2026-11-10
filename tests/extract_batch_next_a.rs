//! Extraction tests for PEM John serialization and Kerberos database exports.

#[path = "../src/extract/krb5db17.rs"]
mod krb5db17;
#[path = "../src/extract/krb5db18.rs"]
mod krb5db18;
#[path = "../src/extract/krb5db_old.rs"]
mod krb5db_old;
#[path = "../src/extract/pem.rs"]
mod pem;

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::{RenderOptions, Tool};

use krb5db_old::Krb5DbOldExtractor;
use krb5db17::Krb5Db17Extractor;
use krb5db18::Krb5Db18Extractor;
use pem::PemExtractor;

static PEM: PemExtractor = PemExtractor;
static KRB5DB17: Krb5Db17Extractor = Krb5Db17Extractor;
static KRB5DB18: Krb5Db18Extractor = Krb5Db18Extractor;
static KRB5DB_OLD: Krb5DbOldExtractor = Krb5DbOldExtractor;

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn expected(kind: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn render(extractor: &dyn Extractor, artifact: &Artifact) -> Vec<String> {
    render_with(extractor, artifact, Tool::Hashcat)
}

fn render_with(extractor: &dyn Extractor, artifact: &Artifact, tool: Tool) -> Vec<String> {
    extractor
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|value| {
            value
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .unwrap()
        })
        .collect()
}

fn extract_error(extractor: &dyn Extractor, artifact: &Artifact) -> ExtractError {
    match extractor.extract(artifact) {
        Ok(_) => panic!("extraction unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn extracted(extractor: &dyn Extractor, artifact: &Artifact) -> Extracted {
    extractor.extract(artifact).expect("extract")
}

#[test]
fn pem_renders_the_john_serialization_for_3des_sha1_keys() {
    let single = artifact("pem", "key-des3-sha1.pem");
    assert!(matches!(
        PEM.probe(&single),
        Probe::Yes(reason) if reason.contains("3DES")
    ));
    assert_eq!(
        render_with(&PEM, &single, Tool::John),
        expected("pem", "key-des3-sha1.hash")
    );

    let multi = artifact("pem", "multi.pem");
    assert!(matches!(PEM.probe(&multi), Probe::Yes(_)));
    assert_eq!(
        render_with(&PEM, &multi, Tool::John),
        expected("pem", "multi.hash")
    );
    assert_eq!(extracted(&PEM, &multi).len(), 2);

    let mixed = artifact("pem", "mixed.pem");
    assert!(matches!(PEM.probe(&mixed), Probe::Yes(_)));
    assert_eq!(
        render_with(&PEM, &mixed, Tool::John),
        expected("pem", "mixed.hash")
    );
}

#[test]
fn pem_renders_pbkdf2_aes_keys() {
    for (name, hash) in [
        ("key-aes-sha1.pem", "key-aes-sha1.john.hash"),
        ("key-aes-sha256.pem", "key-aes-sha256.john.hash"),
    ] {
        let key = artifact("pem", name);
        assert!(matches!(PEM.probe(&key), Probe::Yes(_)), "{name}");
        assert_eq!(
            render_with(&PEM, &key, Tool::John),
            expected("pem", hash),
            "{name}"
        );
    }
}

#[test]
fn pem_probe_requires_structural_armor_evidence() {
    assert_eq!(
        PEM.probe(&Artifact::from_bytes("text", b"not a key".to_vec())),
        Probe::No
    );
    assert_eq!(
        PEM.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );

    let truncated = artifact("pem", "truncated.pem");
    assert!(matches!(PEM.probe(&truncated), Probe::Maybe(_)));
    assert!(matches!(
        extract_error(&PEM, &truncated),
        ExtractError::Invalid(_)
    ));

    assert_eq!(PEM.probe(&artifact("krb5db17", "mimikatz.txt")), Probe::No);
    assert!(PEM.extract(&artifact("krb5db17", "mimikatz.txt")).is_err());
}

#[test]
fn krb5db17_extracts_every_etype_17_key() {
    let mimikatz = artifact("krb5db17", "mimikatz.txt");
    assert!(matches!(
        KRB5DB17.probe(&mimikatz),
        Probe::Yes(reason) if reason.contains("Kerberos")
    ));
    assert_eq!(
        render(&KRB5DB17, &mimikatz),
        expected("krb5db17", "mimikatz.hash")
    );

    let dsinternals = artifact("krb5db17", "dsinternals.txt");
    assert!(matches!(KRB5DB17.probe(&dsinternals), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB17, &dsinternals),
        expected("krb5db17", "dsinternals.hash")
    );
}

#[test]
fn krb5db18_extracts_every_etype_18_key() {
    let mimikatz = artifact("krb5db18", "mimikatz.txt");
    assert!(matches!(KRB5DB18.probe(&mimikatz), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB18, &mimikatz),
        expected("krb5db18", "mimikatz.hash")
    );

    let dsinternals = artifact("krb5db18", "dsinternals.txt");
    assert!(matches!(KRB5DB18.probe(&dsinternals), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB18, &dsinternals),
        expected("krb5db18", "dsinternals.hash")
    );
}

#[test]
fn krb5db_old_extracts_every_legacy_key() {
    let mimikatz = artifact("krb5db-old", "mimikatz.txt");
    assert!(matches!(KRB5DB_OLD.probe(&mimikatz), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB_OLD, &mimikatz),
        expected("krb5db-old", "mimikatz.hash")
    );

    let dsinternals = artifact("krb5db-old", "dsinternals.txt");
    assert!(matches!(KRB5DB_OLD.probe(&dsinternals), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB_OLD, &dsinternals),
        expected("krb5db-old", "dsinternals.hash")
    );
}

#[test]
fn each_kerberos_extractor_selects_only_its_own_etypes() {
    let mixed = artifact("krb5db17", "mimikatz.txt");
    assert_eq!(
        render(&KRB5DB17, &mixed),
        expected("krb5db17", "mimikatz.hash")
    );
    assert_eq!(
        render(&KRB5DB18, &mixed),
        vec![
            "$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7"
        ]
    );
    assert!(matches!(
        extract_error(&KRB5DB_OLD, &mixed),
        ExtractError::Unsupported(_)
    ));

    let only18 = artifact("krb5db18", "mimikatz.txt");
    assert!(matches!(KRB5DB17.probe(&only18), Probe::Yes(_)));
    assert_eq!(
        render(&KRB5DB17, &only18),
        vec!["$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e"]
    );
    assert_eq!(KRB5DB_OLD.probe(&only18), Probe::No);

    let only_legacy = artifact("krb5db-old", "mimikatz.txt");
    assert_eq!(KRB5DB17.probe(&only_legacy), Probe::No);
    assert_eq!(KRB5DB18.probe(&only_legacy), Probe::No);
}

#[test]
fn kerberos_unsalted_exports_are_only_maybe() {
    for (extractor, kind) in [
        (&KRB5DB17 as &dyn Extractor, "krb5db17"),
        (&KRB5DB18, "krb5db18"),
        (&KRB5DB_OLD, "krb5db-old"),
    ] {
        let unsalted = artifact(kind, "norealm.txt");
        assert!(
            matches!(extractor.probe(&unsalted), Probe::Maybe(_)),
            "{kind}"
        );
        assert!(matches!(
            extract_error(extractor, &unsalted),
            ExtractError::Unsupported(_)
        ));
    }
}

#[test]
fn kerberos_rejects_truncated_empty_and_unrelated_input() {
    for (extractor, kind) in [
        (&KRB5DB17 as &dyn Extractor, "krb5db17"),
        (&KRB5DB18, "krb5db18"),
        (&KRB5DB_OLD, "krb5db-old"),
    ] {
        let truncated = artifact(kind, "truncated.txt");
        assert!(matches!(extractor.probe(&truncated), Probe::Maybe(_)));
        assert!(matches!(
            extract_error(extractor, &truncated),
            ExtractError::Invalid(_)
        ));

        let empty = artifact(kind, "empty.txt");
        assert_eq!(extractor.probe(&empty), Probe::No, "{kind}");
        assert!(matches!(
            extract_error(extractor, &empty),
            ExtractError::Unsupported(_)
        ));

        let unrelated = Artifact::from_bytes("text", b"hello world\n".to_vec());
        assert_eq!(extractor.probe(&unrelated), Probe::No, "{kind}");
    }
}
