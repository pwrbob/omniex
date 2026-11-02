//! Extraction tests for the batch 03 extractors.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe, Selection};
use omniex::{HashValue, RenderOptions, Tool};

fn fixture(slug: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(slug)
        .join(name)
}

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_file(&fixture(slug, name)).expect("fixture opens")
}

fn extractor(slug: &str) -> &'static dyn extract::Extractor {
    extract::by_slug(slug).unwrap_or_else(|| panic!("{slug} extractor is registered"))
}

fn rendered(hash: &dyn HashValue, tool: Tool) -> String {
    hash.render(&RenderOptions {
        tool,
        ..RenderOptions::default()
    })
    .expect("hash renders")
}

fn expected(slug: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(slug, name))
        .expect("expected hash file")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn extracted(slug: &str, name: &str, tool: Tool) -> Vec<String> {
    let hashes = extractor(slug)
        .extract(&artifact(slug, name))
        .expect("extraction succeeds");
    hashes
        .iter()
        .map(|hash| rendered(hash.as_ref(), tool))
        .collect()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn pdf_extracts_user_and_owner_dictionaries() {
    assert_eq!(
        extracted("pdf", "encrypted-r3.pdf", Tool::Hashcat),
        expected("pdf", "encrypted-r3.hash")
    );
    assert_eq!(
        extracted("pdf", "encrypted-r2.pdf", Tool::Hashcat),
        expected("pdf", "encrypted-r2.hash")
    );
    assert_eq!(
        extracted("pdf", "encrypted-aes256.pdf", Tool::Hashcat),
        expected("pdf", "encrypted-aes256.hash")
    );
}

#[test]
fn pdf_probe_and_errors() {
    let pdf = extractor("pdf");
    assert!(matches!(
        pdf.probe(&artifact("pdf", "encrypted-r3.pdf")),
        Probe::Yes(reason) if reason == "PDF Standard encryption dictionary"
    ));
    assert_eq!(
        pdf.probe(&Artifact::from_bytes("plain", b"%PDF-1.4\n".to_vec())),
        Probe::No
    );
    assert_eq!(
        pdf.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(
        pdf.extract(&Artifact::from_bytes("empty", Vec::new()))
            .is_err()
    );

    let mut data = std::fs::read(fixture("pdf", "encrypted-r3.pdf")).unwrap();
    data.truncate(600);
    assert!(pdf.extract(&Artifact::from_bytes("short", data)).is_err());

    let missing_id = b"%PDF-1.4\ntrailer<</Encrypt 1 0 R>>\n1 0 obj<</Filter /Standard /V 2 /Length 128 /R 3 /P -4 /O (a) /U (b)>>endobj\n%%EOF"
        .to_vec();
    assert!(matches!(
        pdf.probe(&Artifact::from_bytes("missing-id", missing_id)),
        Probe::Maybe(_)
    ));
}

#[test]
fn pst_extracts_every_checksum() {
    assert_eq!(
        extracted("pst", "checksum-32bit.pst", Tool::John),
        expected("pst", "checksum-32bit.hash")
    );
    assert_eq!(
        extracted("pst", "checksum-compressible.pst", Tool::John),
        expected("pst", "checksum-compressible.hash")
    );
    assert_eq!(
        extracted("pst", "checksum-64bit.pst", Tool::John),
        expected("pst", "checksum-64bit.hash")
    );
}

#[test]
fn pst_probe_and_errors() {
    let pst = extractor("pst");
    assert!(matches!(
        pst.probe(&artifact("pst", "checksum-32bit.pst")),
        Probe::Yes(reason) if reason.starts_with("PST message store header")
    ));
    assert_eq!(
        pst.probe(&Artifact::from_bytes("junk", b"not a pst file".to_vec())),
        Probe::No
    );
    assert_eq!(
        pst.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );

    let mut data = std::fs::read(fixture("pst", "checksum-32bit.pst")).unwrap();
    data.truncate(100);
    assert!(pst.extract(&Artifact::from_bytes("short", data)).is_err());
    assert!(pst.extract(&artifact("pst", "no-password.pst")).is_err());

    let mut header = std::fs::read(fixture("pst", "no-password.pst")).unwrap();
    header[200] = 2;
    assert!(matches!(
        pst.probe(&Artifact::from_bytes("high", header)),
        Probe::Maybe(_)
    ));
}

#[test]
fn sappse_extracts_pkcs12_pbe() {
    assert_eq!(
        extracted("sappse", "encrypted-v2.pse", Tool::John),
        expected("sappse", "encrypted-v2.hash")
    );
}

#[test]
fn sappse_probe_and_errors() {
    let sappse = extractor("sappse");
    assert!(matches!(
        sappse.probe(&artifact("sappse", "encrypted-v2.pse")),
        Probe::Yes(reason) if reason == "SAP PSE encrypted v2 container"
    ));
    assert_eq!(
        sappse.probe(&Artifact::from_bytes("junk", b"not a pse file".to_vec())),
        Probe::No
    );
    assert_eq!(
        sappse.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert!(matches!(
        sappse.probe(&artifact("sappse", "encrypted-v4.pse")),
        Probe::Maybe(_)
    ));
    assert!(
        sappse
            .extract(&artifact("sappse", "unsupported-algorithm.pse"))
            .is_err()
    );
    let data = std::fs::read(fixture("sappse", "encrypted-v2.pse")).unwrap();
    assert!(
        sappse
            .extract(&Artifact::from_bytes("short", data[..20].to_vec()))
            .is_err()
    );
}

#[test]
fn openssl_enc_extracts_salted_payloads() {
    assert_eq!(
        extracted("openssl-enc", "secret.enc", Tool::John),
        expected("openssl-enc", "secret.hash")
    );
    assert_eq!(
        extracted("openssl-enc", "secret-b64.enc", Tool::John),
        expected("openssl-enc", "secret-b64.hash")
    );
}

#[test]
fn openssl_enc_is_maybe_and_requires_type() {
    let openssl = extractor("openssl-enc");
    assert!(!openssl.exact());
    assert!(matches!(
        openssl.probe(&artifact("openssl-enc", "secret.enc")),
        Probe::Maybe(reason) if reason.contains("does not record")
    ));
    assert_eq!(
        openssl.probe(&Artifact::from_bytes("junk", b"not encrypted".to_vec())),
        Probe::No
    );
    assert_eq!(
        openssl.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );

    let auto = omniex()
        .arg("extract")
        .arg(fixture("openssl-enc", "secret.enc"))
        .output()
        .unwrap();
    assert!(!auto.status.success());

    let selected = omniex()
        .arg("extract")
        .arg("--type")
        .arg("openssl-enc")
        .arg("--format")
        .arg("john")
        .arg(fixture("openssl-enc", "secret.enc"))
        .output()
        .unwrap();
    assert!(selected.status.success());
    assert_eq!(
        String::from_utf8(selected.stdout).unwrap().trim_end(),
        expected("openssl-enc", "secret.hash")[0]
    );

    let selected_base64 = omniex()
        .arg("extract")
        .arg("--type")
        .arg("openssl-enc")
        .arg("--format")
        .arg("john")
        .arg(fixture("openssl-enc", "secret-b64.enc"))
        .output()
        .unwrap();
    assert!(selected_base64.status.success());
}

#[test]
fn pkcs12_extracts_the_mac() {
    assert_eq!(
        extracted("pkcs12", "bundle.p12", Tool::Hashcat),
        expected("pkcs12", "bundle.hash")
    );
    assert_eq!(
        extracted("pkcs12", "bundle-sha1.p12", Tool::Hashcat),
        expected("pkcs12", "bundle-sha1.hash")
    );
}

#[test]
fn pkcs12_probe_and_errors() {
    let pkcs12 = extractor("pkcs12");
    assert!(matches!(
        pkcs12.probe(&artifact("pkcs12", "bundle.p12")),
        Probe::Yes(reason) if reason == "PKCS#12 PFX MAC structure"
    ));
    assert_eq!(
        pkcs12.probe(&Artifact::from_bytes("junk", b"not a pkcs12 file".to_vec())),
        Probe::No
    );
    assert_eq!(
        pkcs12.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    let data = std::fs::read(fixture("pkcs12", "bundle.p12")).unwrap();
    assert!(
        pkcs12
            .extract(&Artifact::from_bytes("short", data[..40].to_vec()))
            .is_err()
    );
}

#[test]
fn wrong_type_is_rejected() {
    assert!(
        extractor("sappse")
            .extract(&artifact("pkcs12", "bundle.p12"))
            .is_err()
    );
    assert!(
        extractor("pdf")
            .extract(&artifact("pst", "checksum-32bit.pst"))
            .is_err()
    );
    assert!(
        extractor("pkcs12")
            .extract(&artifact("pdf", "encrypted-r3.pdf"))
            .is_err()
    );
}

#[test]
fn auto_detection_and_all_respect_probe_confidence() {
    let pdf = artifact("pdf", "encrypted-r3.pdf");
    assert!(matches!(
        extract::select(extract::EXTRACTORS, &pdf),
        Selection::Unique(extractor) if extractor.slug() == "pdf"
    ));

    let openssl = artifact("openssl-enc", "secret.enc");
    assert!(matches!(
        extract::select(extract::EXTRACTORS, &openssl),
        Selection::Unconfirmed(_)
    ));
    let all = omniex()
        .arg("extract")
        .arg("--all")
        .arg(fixture("openssl-enc", "secret.enc"))
        .output()
        .unwrap();
    assert!(!all.status.success());

    let json = omniex()
        .arg("extract")
        .arg(fixture("pdf", "encrypted-r3.pdf"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "pdf");

    let pst = omniex()
        .arg("extract")
        .arg(fixture("pst", "checksum-32bit.pst"))
        .arg("--format")
        .arg("john")
        .output()
        .unwrap();
    assert!(pst.status.success());
    assert_eq!(
        String::from_utf8(pst.stdout).unwrap().lines().count(),
        expected("pst", "checksum-32bit.hash").len()
    );
    assert!(matches!(
        extract::select(extract::EXTRACTORS, &artifact("pst", "no-password.pst")),
        Selection::Unique(extractor) if extractor.slug() == "pst"
    ));
}
