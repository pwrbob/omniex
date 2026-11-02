//! Database password hashes embedded in SQL dumps.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/sql")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("dump.sql", std::fs::read(fixture("dump.sql")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn sql_extractors_find_their_hash_types() {
    for (slug, tool) in [
        ("mysql323", Tool::Hashcat),
        ("mysql-sha1", Tool::John),
        ("mysql-a", Tool::Hashcat),
        ("mssql-2000", Tool::Hashcat),
        ("mssql-2005", Tool::Hashcat),
        ("mssql-2012", Tool::Hashcat),
        ("mssql-2025", Tool::Hashcat),
        ("postgres-scram-sha256", Tool::Hashcat),
        ("oracle-h", Tool::Hashcat),
        ("oracle-t", Tool::Hashcat),
    ] {
        let extractor = extract::by_slug(slug).expect("SQL extractor");
        assert!(
            matches!(extractor.probe(&artifact()), Probe::Yes(_)),
            "{slug}"
        );
        let hashes = extractor.extract(&artifact()).expect("extract");
        assert_eq!(hashes.len(), 1, "{slug}");
        assert_eq!(
            hashes[0]
                .render(&RenderOptions {
                    tool,
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
fn sql_dump_is_ambiguous_and_requires_type() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("dump.sql"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous artifact"));

    for slug in ["mysql323", "mssql-2012", "oracle-h"] {
        let output = omniex()
            .args(["extract", "--type", slug])
            .arg(fixture("dump.sql"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}

#[test]
fn sql_extractors_reject_unrelated_text() {
    let plain = Artifact::from_bytes("plain.sql", b"SELECT 1;".to_vec());
    for slug in [
        "mysql323",
        "mysql-sha1",
        "mysql-a",
        "mssql-2000",
        "mssql-2005",
        "mssql-2012",
        "mssql-2025",
        "postgres-scram-sha256",
        "oracle-h",
        "oracle-t",
    ] {
        let extractor = extract::by_slug(slug).expect("SQL extractor");
        assert_eq!(extractor.probe(&plain), Probe::No, "{slug}");
    }
}
