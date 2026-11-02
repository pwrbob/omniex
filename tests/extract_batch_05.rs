//! Extraction for XCA, KeePass, Password Safe v2, and Clipperz artifacts.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{RenderOptions, Tool};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn expected(slug: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(slug, name))
        .expect("read expected fixture")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(slug, name)).expect("read artifact"),
    )
}

fn bytes_artifact(name: &str, data: Vec<u8>) -> Artifact {
    Artifact::from_bytes(name, data)
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn render(hashes: &[Box<dyn omniex::HashValue>], tool: Tool) -> Vec<String> {
    hashes
        .iter()
        .map(|value| {
            value
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .expect("render extracted hash")
        })
        .collect()
}

#[test]
fn keepass_probe_and_extract_v3() {
    let extractor = extract::by_slug("keepass").expect("KeePass extractor");
    let data = artifact("keepass", "sample.kdbx");
    assert!(matches!(extractor.probe(&data), Probe::Yes(_)));

    let hashes = extractor.extract(&data).expect("extract v3 database");
    assert_eq!(hashes.len(), 1);
    let expected = expected("keepass", "sample.hash");
    assert_eq!(render(&hashes, Tool::Hashcat), expected);
    assert_eq!(render(&hashes, Tool::John), expected);

    assert_eq!(
        extractor.probe(&bytes_artifact("bad", b"not a keypass".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&bytes_artifact("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn keepass_rejects_v4_and_truncated_headers() {
    let extractor = extract::by_slug("keepass").expect("KeePass extractor");
    assert_eq!(
        extractor.probe(&artifact("keepass4", "sample.kdbx")),
        Probe::No
    );

    let data = std::fs::read(fixture("keepass", "sample.kdbx")).unwrap();
    let truncated = bytes_artifact("truncated.kdbx", data[..40].to_vec());
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn keepass4_probe_and_extract_v4() {
    let extractor = extract::by_slug("keepass4").expect("KeePass4 extractor");
    let data = artifact("keepass4", "sample.kdbx");
    assert!(matches!(extractor.probe(&data), Probe::Yes(_)));

    let hashes = extractor.extract(&data).expect("extract v4 database");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        render(&hashes, Tool::Hashcat),
        expected("keepass4", "sample.hash")
    );
    assert_eq!(
        extractor.probe(&artifact("keepass", "sample.kdbx")),
        Probe::No
    );
}

#[test]
fn keepass4_rejects_unsupported_kdf_and_truncation() {
    let extractor = extract::by_slug("keepass4").expect("KeePass4 extractor");
    let mut data = std::fs::read(fixture("keepass4", "sample.kdbx")).unwrap();
    let uuid = data
        .windows(5)
        .position(|window| window == b"$UUID")
        .expect("KDF UUID key");
    data[uuid - 6] = 0x02;
    let broken = bytes_artifact("bad-kdf.kdbx", data);
    assert_eq!(extractor.probe(&broken), Probe::No);
    assert!(extractor.extract(&broken).is_err());

    let raw = std::fs::read(fixture("keepass4", "sample.kdbx")).unwrap();
    let truncated = bytes_artifact("truncated.kdbx", raw[..60].to_vec());
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn pwsafe_v2_probes_with_extension_and_extracts_header() {
    let extractor = extract::by_slug("pwsafe-v2").expect("Password Safe v2 extractor");
    let data = artifact("pwsafe-v2", "sample.dat");
    assert!(matches!(
        extractor.probe(&data),
        Probe::Maybe(reason) if reason == "Password Safe v2 database header"
    ));
    assert_eq!(
        extractor.probe(&bytes_artifact(
            "sample.psafe3",
            std::fs::read(fixture("pwsafe-v2", "sample.dat")).unwrap()
        )),
        Probe::No
    );

    let hashes = extractor.extract(&data).expect("extract v2 header");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        render(&hashes, Tool::Hashcat),
        expected("pwsafe-v2", "sample.hash")
    );

    let raw = std::fs::read(fixture("pwsafe-v2", "sample.dat")).unwrap();
    assert!(
        extractor
            .extract(&bytes_artifact("short.dat", raw[..100].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .probe(&bytes_artifact("empty.dat", Vec::new()))
            .eq(&Probe::No)
    );
}

#[test]
fn pwsafe_v2_never_auto_detects() {
    let output = omniex()
        .arg("extract")
        .arg(fixture("pwsafe-v2", "sample.dat"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("pwsafe-v2", "sample.dat"))
        .output()
        .unwrap();
    assert_eq!(all.status.code(), Some(1));
    assert!(all.stdout.is_empty());

    let explicit = omniex()
        .arg("extract")
        .arg("--type")
        .arg("pwsafe-v2")
        .arg(fixture("pwsafe-v2", "sample.dat"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8_lossy(&explicit.stdout).trim_end(),
        expected("pwsafe-v2", "sample.hash")[0]
    );
}

#[test]
fn pwsafe_v2_rejects_v3_databases() {
    let extractor = extract::by_slug("pwsafe-v2").expect("Password Safe v2 extractor");
    let mut data = vec![0; 200];
    data[..4].copy_from_slice(b"PWS3");
    assert!(
        extractor
            .extract(&bytes_artifact("sample.dat", data))
            .is_err()
    );
}

#[test]
fn xca_probes_sqlite_and_extracts_settings_hash() {
    let extractor = extract::by_slug("xca").expect("XCA extractor");
    let data = artifact("xca", "sample.xdb");
    assert!(matches!(extractor.probe(&data), Probe::Yes(_)));

    let hashes = extractor.extract(&data).expect("extract XCA database");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        render(&hashes, Tool::Hashcat),
        expected("xca", "sample.hash")
    );

    assert_eq!(
        extractor.probe(&bytes_artifact("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&bytes_artifact("text", b"not a database at all".to_vec())),
        Probe::No
    );
}

#[test]
fn xca_requires_the_password_setting() {
    let extractor = extract::by_slug("xca").expect("XCA extractor");
    let mut data = std::fs::read(fixture("xca", "sample.xdb")).unwrap();
    let key = data
        .windows(6)
        .position(|window| window == b"pwhash")
        .unwrap();
    data[key + 5] = b'x';
    let broken = bytes_artifact("broken.xdb", data);
    assert_eq!(extractor.probe(&broken), Probe::No);
    assert!(extractor.extract(&broken).is_err());

    let raw = std::fs::read(fixture("xca", "sample.xdb")).unwrap();
    assert!(
        extractor
            .extract(&bytes_artifact("short.xdb", raw[..100].to_vec()))
            .is_err()
    );
}

#[test]
fn xca_rejects_corrupt_page_size() {
    let extractor = extract::by_slug("xca").expect("XCA extractor");
    let mut data = std::fs::read(fixture("xca", "sample.xdb")).unwrap();
    data[16] = 0x00;
    data[17] = 0x03;
    let corrupt = bytes_artifact("corrupt.xdb", data);
    assert!(matches!(extractor.probe(&corrupt), Probe::Maybe(_)));
    assert!(extractor.extract(&corrupt).is_err());
}

#[test]
fn clipperz_probes_and_extracts_every_user() {
    let extractor = extract::by_slug("clipperz").expect("Clipperz extractor");
    let data = artifact("clipperz", "sample.html");
    assert!(matches!(extractor.probe(&data), Probe::Yes(_)));

    let hashes = extractor.extract(&data).expect("extract Clipperz export");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        render(&hashes, Tool::John),
        expected("clipperz", "sample.hash")
    );
    assert_eq!(
        extractor.probe(&bytes_artifact("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&bytes_artifact("text", b"nothing here".to_vec())),
        Probe::No
    );
}

#[test]
fn clipperz_rejects_broken_exports() {
    let extractor = extract::by_slug("clipperz").expect("Clipperz extractor");
    let no_users = bytes_artifact(
        "empty.html",
        b"_clipperz_dump_data_ = { users: { } };".to_vec(),
    );
    assert!(extractor.extract(&no_users).is_err());

    let broken = bytes_artifact(
        "broken.html",
        b"_clipperz_dump_data_ = { users: { 'a': { s: '1', v: '2'".to_vec(),
    );
    assert!(extractor.extract(&broken).is_err());
}

#[test]
fn auto_detection_finds_the_unique_extractors() {
    let cases = [
        ("keepass", "sample.kdbx", "hashcat"),
        ("keepass4", "sample.kdbx", "hashcat"),
        ("xca", "sample.xdb", "hashcat"),
    ];
    for (slug, name, format) in cases {
        let output = omniex()
            .arg("extract")
            .arg(fixture(slug, name))
            .args(["--format", format])
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim_end(),
            expected(slug, "sample.hash")[0],
            "{slug}"
        );
    }

    let clipperz = omniex()
        .arg("extract")
        .arg(fixture("clipperz", "sample.html"))
        .args(["--format", "john"])
        .output()
        .unwrap();
    assert!(clipperz.status.success());
    assert_eq!(
        String::from_utf8_lossy(&clipperz.stdout)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        expected("clipperz", "sample.hash")
    );
}

#[test]
fn explicit_wrong_type_reports_extraction_failure() {
    let output = omniex()
        .arg("extract")
        .arg("--type")
        .arg("clipperz")
        .arg(fixture("keepass", "sample.kdbx"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot extract `clipperz`"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
