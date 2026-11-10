//! Encrypted OpenDocument package extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/odf")
        .join(name)
}

fn artifact() -> Artifact {
    Artifact::from_bytes("sample.odt", std::fs::read(fixture("sample.odt")).unwrap())
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn odf_probe_requires_an_encrypted_manifest() {
    let extractor = extract::by_slug("odf").expect("ODF extractor");
    assert!(matches!(
        extractor.probe(&artifact()),
        Probe::Yes(reason) if reason == "encrypted OpenDocument manifest"
    ));
    let plain = scratch_zip("plain.odt", "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"><manifest:file-entry manifest:full-path=\"content.xml\"/></manifest:manifest>".as_bytes());
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain.odt", plain)),
        Probe::No
    );
}

fn scratch_zip(name: &str, manifest: &[u8]) -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    let _ = name;
    let mut data = Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut data);
        zip.start_file("META-INF/manifest.xml", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(manifest).unwrap();
        zip.start_file("content.xml", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"content").unwrap();
        zip.finish().unwrap();
    }
    data.into_inner()
}

#[test]
fn odf_extracts_the_package_hash() {
    let extractor = extract::by_slug("odf").expect("ODF extractor");
    let hashes = extractor.extract(&artifact()).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(18400)));
    assert!(hashes[0].modes().contains(&Mode::John("ODF")));
}

#[test]
fn odf_uses_the_content_entry_encryption_parameters() {
    let manifest = br#"<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
 <manifest:file-entry manifest:full-path="meta.xml">
  <manifest:encryption-data manifest:checksum="AAECAwQFBgcICQoLDA0ODxAREhM=" manifest:checksum-type="SHA1" manifest:algorithm-name="aes256-cbc" manifest:initialisation-vector="AAECAwQFBgc=" manifest:salt="AAAAAAAAAAAAAAAAAAAAAA==" manifest:iteration-count="1" manifest:key-size="256" manifest:start-key-generation-name="SHA1"/>
 </manifest:file-entry>
 <manifest:file-entry manifest:full-path="content.xml">
  <manifest:encryption-data manifest:checksum="AAECAwQFBgcICQoLDA0ODxAREhM=" manifest:checksum-type="SHA1" manifest:algorithm-name="aes256-cbc" manifest:initialisation-vector="AAECAwQFBgc=" manifest:salt="AAECAwQFBgcICQoLDA0ODw==" manifest:iteration-count="10240" manifest:key-size="256" manifest:start-key-generation-name="SHA1"/>
 </manifest:file-entry>
</manifest:manifest>"#;
    let extractor = extract::by_slug("odf").expect("ODF extractor");
    let hashes = extractor
        .extract(&Artifact::from_bytes(
            "multi-entry.odt",
            scratch_zip("multi-entry.odt", manifest),
        ))
        .expect("extract");
    let rendered = hashes[0].render(&RenderOptions::default()).unwrap();
    assert!(rendered.contains("*10240*256*"), "{rendered}");
    assert!(rendered.contains("*16*000102030405060708090a0b0c0d0e0f*"));
}

#[test]
fn odf_auto_detects_and_reports_json() {
    let auto = omniex()
        .arg("extract")
        .arg(fixture("sample.odt"))
        .output()
        .unwrap();
    assert!(auto.status.success());

    let json = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("sample.odt"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "odf");
}

#[test]
fn odf_rejects_unsupported_and_plain_packages() {
    let extractor = extract::by_slug("odf").expect("ODF extractor");
    let data = std::fs::read(fixture("sample.odt")).unwrap();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("bad", data[..50].to_vec()))
            .is_err()
    );
    let plain = scratch_zip("plain.odt", "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"/>".as_bytes());
    assert!(
        extractor
            .extract(&Artifact::from_bytes("plain.odt", plain))
            .is_err()
    );
}
