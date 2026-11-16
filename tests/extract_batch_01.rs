//! Extraction for ZipCrypto, SecureZIP, and RAR3 archives.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(slug, name)).expect("read artifact"),
    )
}

fn expected(slug: &str) -> String {
    expected_file(slug, "archive.hash")
}

fn expected_file(slug: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(slug, name))
        .expect("read expected hash")
        .trim_end()
        .to_owned()
}

fn with_options(artifact: Artifact, options: &[&str]) -> Artifact {
    let mut set = extract::ExtractOptions::new();
    for name in options {
        assert!(set.set(*name, None), "duplicate option {name}");
    }
    artifact.with_options(set)
}

fn rendered(hashes: &extract::Extracted) -> Vec<String> {
    hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).expect("render"))
        .collect()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pkzip_probe_requires_a_zipcrypto_entry() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    assert!(matches!(
        extractor.probe(&artifact("pkzip", "archive.zip")),
        Probe::Yes(reason) if reason == "PKZIP ZipCrypto entry"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"PK\x03\x04plain".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn pkzip_extracts_the_entry() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let hashes = extractor
        .extract(&artifact("pkzip", "archive.zip"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("pkzip")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(17210)));
    assert!(!hashes[0].modes().contains(&Mode::Hashcat(17200)));
    assert!(hashes[0].modes().contains(&Mode::Hashcat(17225)));
    assert!(hashes[0].modes().contains(&Mode::John("PKZIP")));
}

#[test]
fn pkzip_keeps_every_entry_in_one_hash() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let hashes = extractor
        .extract(&artifact("pkzip", "multi.zip"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(rendered(&hashes), [expected_file("pkzip", "multi.hash")]);
    let rendered = hashes[0].render(&RenderOptions::default()).unwrap();
    assert!(rendered.starts_with("$pkzip$2*"), "{rendered}");
}

#[test]
fn pkzip_checksum_only_matches_zip2john() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let artifact = with_options(artifact("pkzip", "multi.zip"), &["checksum-only"]);
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(
        rendered(&hashes),
        [expected_file("pkzip", "multi-checksum.hash")]
    );
    let rendered = hashes[0].render(&RenderOptions::default()).unwrap();
    assert!(!rendered.contains("*2*0*"), "{rendered}");
}

#[test]
fn pkzip_reads_zip64_central_directories() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    assert!(matches!(
        extractor.probe(&artifact("pkzip", "zip64.zip")),
        Probe::Yes(reason) if reason == "PKZIP ZipCrypto entry"
    ));
    let hashes = extractor
        .extract(&artifact("pkzip", "zip64.zip"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected_file("pkzip", "zip64.hash")]);
}

#[test]
fn pkzip_uses_the_last_central_directory() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let mut data = std::fs::read(fixture("pkzip", "archive.zip")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.zip", data))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    let rendered = hashes[0].render(&RenderOptions::default()).unwrap();
    assert!(rendered.starts_with("$pkzip$1*"), "{rendered}");
}

#[test]
fn pkzip_rejects_conflicting_options() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let artifact = with_options(
        artifact("pkzip", "multi.zip"),
        &["checksum-only", "full-data"],
    );
    assert!(extractor.extract(&artifact).is_err());
}

#[test]
fn pkzip_auto_detects_zip64_and_large_archives() {
    let zip64 = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "zip64.zip"))
        .output()
        .unwrap();
    assert!(zip64.status.success());
    assert_eq!(
        String::from_utf8(zip64.stdout).unwrap().trim_end(),
        expected_file("pkzip", "zip64.hash")
    );

    let multi = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "multi.zip"))
        .output()
        .unwrap();
    assert!(multi.status.success());
    assert_eq!(
        String::from_utf8(multi.stdout).unwrap().trim_end(),
        expected_file("pkzip", "multi.hash")
    );
}

#[test]
fn pkzip_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "archive.zip"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("pkzip", "archive.zip"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["results"][0]["type"], "pkzip");
}

#[test]
fn pkzip_rejects_truncated_and_other_formats() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let data = std::fs::read(fixture("pkzip", "archive.zip")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..20].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "securezip",
                std::fs::read(fixture("securezip", "archive.zip")).unwrap()
            ))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
}

#[test]
fn securezip_probe_requires_a_strong_encryption_header() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    assert!(matches!(
        extractor.probe(&artifact("securezip", "archive.zip")),
        Probe::Yes(reason) if reason == "SecureZIP strong-encryption header"
    ));
    assert_eq!(
        extractor.probe(&artifact("pkzip", "archive.zip")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn securezip_extracts_the_entry() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let hashes = extractor
        .extract(&artifact("securezip", "archive.zip"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("securezip")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23003)));
    assert!(hashes[0].modes().contains(&Mode::John("securezip")));
}

#[test]
fn securezip_finds_every_entry() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let mut data = std::fs::read(fixture("securezip", "archive.zip")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.zip", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn securezip_rejects_truncated_and_other_formats() {
    let extractor = extract::by_slug("securezip").expect("SecureZIP extractor");
    let data = std::fs::read(fixture("securezip", "archive.zip")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..40].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&artifact("pkzip", "archive.zip"))
            .is_err()
    );
}

#[test]
fn rar3p_probe_requires_a_file_header() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    assert!(matches!(
        extractor.probe(&artifact("rar3p", "archive.rar")),
        Probe::Yes(reason) if reason == "RAR3 encrypted file header"
    ));
    assert_eq!(
        extractor.probe(&artifact("rar3hp", "archive.rar")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("text", b"not a rar".to_vec())),
        Probe::No
    );
}

#[test]
fn rar3p_extracts_the_entry() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let hashes = extractor
        .extract(&artifact("rar3p", "archive.rar"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("rar3p")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23700)));
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23800)));
}

#[test]
fn rar3p_finds_hashes_in_later_archives() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let mut data = std::fs::read(fixture("rar3p", "archive.rar")).unwrap();
    let single = data.clone();
    data.extend_from_slice(&single);
    let hashes = extractor
        .extract(&Artifact::from_bytes("two.rar", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn rar3p_rejects_truncated_archives() {
    let extractor = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let data = std::fs::read(fixture("rar3p", "archive.rar")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..30].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );
}

#[test]
fn rar3hp_probe_requires_an_encrypted_header() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    assert!(matches!(
        extractor.probe(&artifact("rar3hp", "archive.rar")),
        Probe::Yes(reason) if reason == "RAR3 encrypted header"
    ));
    assert_eq!(
        extractor.probe(&artifact("rar3p", "archive.rar")),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
}

#[test]
fn rar3hp_extracts_the_trailer() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    let hashes = extractor
        .extract(&artifact("rar3hp", "archive.rar"))
        .expect("extract");
    assert_eq!(rendered(&hashes), [expected("rar3hp")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(12500)));
    assert!(hashes[0].modes().contains(&Mode::John("rar")));
}

#[test]
fn rar3hp_rejects_truncated_and_plain_archives() {
    let extractor = extract::by_slug("rar3hp").expect("RAR3-hp extractor");
    let data = std::fs::read(fixture("rar3hp", "archive.rar")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("short", data[..20].to_vec()))
            .is_err()
    );
    assert!(
        extractor
            .extract(&artifact("rar3p", "archive.rar"))
            .is_err()
    );
}

#[test]
fn rar3_archives_are_disambiguated_by_header_encryption() {
    let rar3p = extract::by_slug("rar3p").expect("RAR3-p extractor");
    let rar3hp = extract::by_slug("rar3hp").expect("RAR3-hp extractor");

    assert!(matches!(
        rar3p.probe(&artifact("rar3p", "archive.rar")),
        Probe::Yes(_)
    ));
    assert_eq!(rar3hp.probe(&artifact("rar3p", "archive.rar")), Probe::No);

    assert!(matches!(
        rar3hp.probe(&artifact("rar3hp", "archive.rar")),
        Probe::Yes(_)
    ));
    assert_eq!(rar3p.probe(&artifact("rar3hp", "archive.rar")), Probe::No);
}

fn scanned_archive(entries: &[(&str, usize)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data_len) in entries {
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&10u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        out.extend_from_slice(&(*data_len as u32).to_le_bytes());
        out.extend_from_slice(&(*data_len as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend(std::iter::repeat_n(0x41u8, *data_len));
    }
    out
}

#[test]
fn pkzip_requires_full_data_above_the_hashcat_limit() {
    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let data = scanned_archive(&[("big.bin", 400 * 1024)]);
    let error = extractor
        .extract(&Artifact::from_bytes("big.zip", data.clone()))
        .err()
        .expect("oversized entry must be refused");
    assert!(error.to_string().contains("--opt checksum-only"), "{error}");

    let artifact = with_options(Artifact::from_bytes("big.zip", data), &["full-data"]);
    let hashes = extractor.extract(&artifact).expect("extract");
    assert!(hashes[0].streams());

    let mut out = Vec::new();
    hashes[0]
        .render_to(&RenderOptions::default(), &mut out)
        .expect("stream");
    let text = String::from_utf8(out).expect("ascii");
    assert!(text.starts_with("$pkzip$1*2*2*0*"), "{text}");
    assert!(text.ends_with("*$/pkzip$"));
    assert!(text.contains(&"41".repeat(64)), "hex data is streamed");
}

#[test]
fn pkzip_cli_validates_options() {
    let checksum = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "multi.zip"))
        .arg("--type")
        .arg("pkzip")
        .args(["--opt", "checksum-only"])
        .output()
        .unwrap();
    assert!(checksum.status.success());
    assert_eq!(
        String::from_utf8(checksum.stdout).unwrap().trim_end(),
        expected_file("pkzip", "multi-checksum.hash")
    );

    let unknown = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "multi.zip"))
        .arg("--type")
        .arg("pkzip")
        .args(["--opt", "deep"])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("does not accept `--opt deep`"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );

    let valued = omniex()
        .arg("extract")
        .arg(fixture("pkzip", "multi.zip"))
        .arg("--type")
        .arg("pkzip")
        .args(["--opt", "checksum-only=1"])
        .output()
        .unwrap();
    assert!(!valued.status.success());
    assert!(
        String::from_utf8_lossy(&valued.stderr).contains("does not take a value"),
        "{}",
        String::from_utf8_lossy(&valued.stderr)
    );
}

#[test]
fn show_lists_extractor_options() {
    let json = omniex().args(["show", "pkzip", "--json"]).output().unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let names = value["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|option| option["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["checksum-only", "full-data"]);

    let human = omniex().args(["show", "bitlocker"]).output().unwrap();
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("deep"));

    let encdv = omniex().args(["show", "encdv", "--json"]).output().unwrap();
    assert!(encdv.status.success());
    let value: serde_json::Value = serde_json::from_slice(&encdv.stdout).unwrap();
    let companions = value["companions"].as_array().unwrap();
    assert_eq!(companions.len(), 2);
    assert_eq!(companions[0]["name"], "enckey");
    assert_eq!(companions[0]["required"], false);
    assert_eq!(companions[1]["name"], "keychain");
    assert_eq!(companions[1]["required"], false);

    let human = omniex().args(["show", "encdv"]).output().unwrap();
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("Companion"), "{text}");
    assert!(text.contains("enckey"), "{text}");
    assert!(text.contains("keychain"), "{text}");

    let lpcli = omniex().args(["show", "lpcli", "--json"]).output().unwrap();
    assert!(lpcli.status.success());
    let value: serde_json::Value = serde_json::from_slice(&lpcli.stdout).unwrap();
    let required = value["companions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|companion| companion["required"] == true)
        .count();
    assert_eq!(required, 2);
}

#[test]
fn pkzip_streamed_values_require_hash_output() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pkzip-streamed.zip");
    std::fs::write(&path, scanned_archive(&[("big.bin", 400 * 1024)])).expect("write archive");

    let rejected = omniex()
        .arg("extract")
        .arg(&path)
        .arg("--type")
        .arg("pkzip")
        .args(["--opt", "full-data", "--format", "json"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("streams its payload"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let streamed = omniex()
        .arg("extract")
        .arg(&path)
        .arg("--type")
        .arg("pkzip")
        .args(["--opt", "full-data"])
        .output()
        .unwrap();
    assert!(streamed.status.success());

    let extractor = extract::by_slug("pkzip").expect("PKZIP extractor");
    let hashes = extractor
        .extract(&with_options(
            Artifact::from_bytes("big.zip", scanned_archive(&[("big.bin", 400 * 1024)])),
            &["full-data"],
        ))
        .expect("extract");
    let expected = hashes[0].render(&RenderOptions::default()).expect("render");
    assert_eq!(
        String::from_utf8(streamed.stdout).unwrap().trim_end(),
        expected
    );
}
