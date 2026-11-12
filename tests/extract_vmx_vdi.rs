//! VMware VMX and VirtualBox VDI extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, Probe};
use omniex::{Mode, RenderOptions, Tool};

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
fn vmx_probe_requires_a_supported_key_safe() {
    let extractor = extract::by_slug("vmx-keysafe").expect("VMX extractor");
    assert!(matches!(
        extractor.probe(&artifact("vmx", "sample.vmx")),
        Probe::Yes(reason) if reason == "VMware VMX encryption.keySafe"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes(
            "plain",
            b"displayName = \"x\"".to_vec()
        )),
        Probe::No
    );
}

#[test]
fn vmx_extracts_the_john_serialization() {
    let extractor = extract::by_slug("vmx-keysafe").expect("VMX extractor");
    let hashes = extractor
        .extract(&artifact("vmx", "sample.vmx"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("vmx", "sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("vmx")));
}

#[test]
fn vdi_probe_requires_a_supported_key_store() {
    let extractor = extract::by_slug("vdi").expect("VDI extractor");
    assert!(matches!(
        extractor.probe(&artifact("vdi", "sample.vbox")),
        Probe::Yes(reason) if reason == "VirtualBox encrypted key store"
    ));
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain", b"<VirtualBox/>".to_vec())),
        Probe::No
    );
}

#[test]
fn vdi_extracts_the_john_serialization() {
    let extractor = extract::by_slug("vdi").expect("VDI extractor");
    let hashes = extractor
        .extract(&artifact("vdi", "sample.vbox"))
        .expect("extract");
    assert_eq!(
        hashes[0]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .unwrap(),
        std::fs::read_to_string(fixture("vdi", "sample.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::John("vdi")));
}

#[test]
fn virtualbox_extracts_the_hashcat_serialization() {
    let extractor = extract::by_slug("virtualbox").expect("VirtualBox extractor");
    let hashes = extractor
        .extract(&artifact("vdi", "sample.vbox"))
        .expect("extract");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        std::fs::read_to_string(fixture("vdi", "sample.vbox.hash"))
            .unwrap()
            .trim_end()
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(27600)));
}

#[test]
fn vmx_and_vdi_auto_detect_in_the_cli() {
    let vmx = omniex()
        .arg("extract")
        .arg(fixture("vmx", "sample.vmx"))
        .args(["--type", "vmx-keysafe", "--tool", "john"])
        .output()
        .unwrap();
    assert!(vmx.status.success());
    let json = omniex()
        .arg("extract")
        .arg(fixture("vmx", "sample.vmx"))
        .args(["--type", "vmware-vmx", "--format", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value[0]["type"], "vmware-vmx");

    let ambiguous = omniex()
        .arg("extract")
        .arg(fixture("vdi", "sample.vbox"))
        .output()
        .unwrap();
    assert_eq!(ambiguous.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous artifact"));

    for (slug, format) in [("vdi", "john"), ("virtualbox", "hashcat")] {
        let output = omniex()
            .args(["extract", "--type", slug, "--tool", format])
            .arg(fixture("vdi", "sample.vbox"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{slug}");
    }
}

#[test]
fn vmx_and_vdi_reject_truncated_input() {
    let vmx = extract::by_slug("vmx-keysafe").expect("VMX extractor");
    assert!(
        vmx.extract(&Artifact::from_bytes(
            "bad.vmx",
            b"encryption.keySafe = \"phrase/notbase64\"".to_vec()
        ))
        .is_err()
    );
    let vdi = extract::by_slug("vdi").expect("VDI extractor");
    assert!(
        vdi.extract(&Artifact::from_bytes(
            "bad.vbox",
            b"<VirtualBox><Property name=\"CRYPT/KeyId\" value=\"x\"/><Property name=\"CRYPT/KeyStore\" value=\"U0NO\"/></VirtualBox>".to_vec()
        ))
        .is_err()
    );
}
