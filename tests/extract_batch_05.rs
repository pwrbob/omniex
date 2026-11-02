//! Extraction for FileVault 2, APFS, Samsung Android FDE, fscrypt, and VMware VMX.

#[path = "../src/extract/android_fde_samsung.rs"]
mod android_fde_samsung;
#[path = "../src/extract/apfs.rs"]
mod apfs;
#[path = "../src/extract/filevault2.rs"]
mod filevault2;
#[path = "../src/extract/fscrypt.rs"]
mod fscrypt;
#[path = "../src/extract/vmware_vmx.rs"]
mod vmware_vmx;

use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, Extractor, MemorySource, Probe, Selection, select};
use omniex::{HashValue, Mode, RenderOptions, Tool};

use android_fde_samsung::AndroidFdeSamsungExtractor;
use apfs::ApfsExtractor;
use filevault2::FileVault2Extractor;
use fscrypt::FscryptExtractor;
use vmware_vmx::VmwareVmxExtractor;

static FILEVAULT2: FileVault2Extractor = FileVault2Extractor;
static APFS: ApfsExtractor = ApfsExtractor;
static SAMSUNG: AndroidFdeSamsungExtractor = AndroidFdeSamsungExtractor;
static FSCRYPT: FscryptExtractor = FscryptExtractor;
static VMWARE: VmwareVmxExtractor = VmwareVmxExtractor;

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
    std::fs::read_to_string(fixture(slug, "sample.hash"))
        .expect("read expected hash")
        .trim_end()
        .to_owned()
}

fn render(values: &[Box<dyn HashValue>], tool: Tool) -> Vec<String> {
    values
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

fn bytes(name: &str, data: Vec<u8>) -> Artifact {
    Artifact::from_bytes(name, data)
}

#[test]
fn filevault2_probes_and_extracts_the_corestorage_user() {
    let data = artifact("filevault2", "sample.img");
    assert!(matches!(
        FILEVAULT2.probe(&data),
        Probe::Yes(reason) if reason == "CoreStorage encryption context"
    ));
    let hashes = FILEVAULT2
        .extract(&data)
        .expect("extract CoreStorage volume");
    assert_eq!(hashes.len(), 1);
    assert_eq!(render(&hashes, Tool::Hashcat), [expected("filevault2")]);
    assert_eq!(render(&hashes, Tool::John), [expected("filevault2")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(16700)));
    assert!(hashes[0].modes().contains(&Mode::John("FVDE")));
}

#[test]
fn filevault2_scan_collects_every_volume() {
    let mut data = std::fs::read(fixture("filevault2", "sample.img")).unwrap();
    let copy = data.clone();
    data.extend_from_slice(&copy);
    let hashes = FILEVAULT2
        .extract(&bytes("two-volumes.img", data))
        .expect("extract two volumes");
    assert_eq!(hashes.len(), 2);
    assert_eq!(render(&hashes, Tool::Hashcat)[0], expected("filevault2"));
}

#[test]
fn filevault2_rejects_empty_wrong_and_truncated_input() {
    assert_eq!(FILEVAULT2.probe(&bytes("empty", Vec::new())), Probe::No);
    assert_eq!(
        FILEVAULT2.probe(&bytes("text", b"not a corestorage volume".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("filevault2", "sample.img")).unwrap();
    let truncated = bytes("truncated.img", data[..data.len() - 100].to_vec());
    assert_eq!(FILEVAULT2.probe(&truncated), Probe::No);
    assert!(FILEVAULT2.extract(&truncated).is_err());

    let mut unsupported = data.clone();
    unsupported[172..176].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        FILEVAULT2.probe(&bytes("unsupported.img", unsupported)),
        Probe::No
    );

    let mut corrupt = data;
    corrupt[88] = b'X';
    assert_eq!(FILEVAULT2.probe(&bytes("corrupt.img", corrupt)), Probe::No);
}

#[test]
fn apfs_probes_and_extracts_the_volume_user() {
    let data = artifact("apfs", "sample.img");
    assert!(matches!(
        APFS.probe(&data),
        Probe::Yes(reason) if reason == "APFS container keybag"
    ));
    let hashes = APFS.extract(&data).expect("extract APFS container");
    assert_eq!(hashes.len(), 1);
    assert_eq!(render(&hashes, Tool::Hashcat), [expected("apfs")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(18300)));
}

#[test]
fn apfs_scan_collects_every_container() {
    let mut data = std::fs::read(fixture("apfs", "sample.img")).unwrap();
    let copy = data.clone();
    data.extend_from_slice(&copy);
    let hashes = APFS
        .extract(&bytes("two-containers.img", data))
        .expect("extract two containers");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn apfs_rejects_empty_wrong_and_truncated_input() {
    assert_eq!(APFS.probe(&bytes("empty", Vec::new())), Probe::No);
    assert_eq!(
        APFS.probe(&bytes("text", b"not an apfs container".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("apfs", "sample.img")).unwrap();
    let truncated = bytes("truncated.img", data[..20 * 1024].to_vec());
    assert_eq!(APFS.probe(&truncated), Probe::No);
    assert!(APFS.extract(&truncated).is_err());
}

#[test]
fn samsung_probes_and_extracts_the_dek_footer() {
    let data = artifact("android-fde-samsung", "sample.img");
    assert!(matches!(
        SAMSUNG.probe(&data),
        Probe::Yes(reason) if reason == "Samsung Android FDE footer"
    ));
    let hashes = SAMSUNG
        .extract(&data)
        .expect("extract Samsung Android FDE footer");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        render(&hashes, Tool::Hashcat),
        [expected("android-fde-samsung")]
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(12900)));
}

#[test]
fn samsung_rejects_unknown_key_sizes() {
    let mut data = std::fs::read(fixture("android-fde-samsung", "sample.img")).unwrap();
    let footer = data.len() - 0x4000;
    data[footer + 16..footer + 20].copy_from_slice(&16u32.to_le_bytes());
    let unsupported = bytes("unsupported.img", data);
    assert_eq!(SAMSUNG.probe(&unsupported), Probe::No);
    assert!(SAMSUNG.extract(&unsupported).is_err());
}

#[test]
fn samsung_scan_collects_every_footer() {
    let mut data = std::fs::read(fixture("android-fde-samsung", "sample.img")).unwrap();
    let copy = data.clone();
    data.extend_from_slice(&copy);
    let hashes = SAMSUNG
        .extract(&bytes("two-footers.img", data))
        .expect("extract two footers");
    assert_eq!(hashes.len(), 2);
}

#[test]
fn samsung_rejects_empty_wrong_and_truncated_input() {
    assert_eq!(SAMSUNG.probe(&bytes("empty", Vec::new())), Probe::No);
    assert_eq!(
        SAMSUNG.probe(&bytes("text", b"not a footer at all".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("android-fde-samsung", "sample.img")).unwrap();
    let truncated = bytes("truncated.img", data[..0x2080].to_vec());
    assert_eq!(SAMSUNG.probe(&truncated), Probe::No);
    assert!(SAMSUNG.extract(&truncated).is_err());
}

#[test]
fn fscrypt_probes_as_a_candidate_and_extracts_the_protector() {
    let data = artifact("fscrypt", "sample.bin");
    assert!(!FSCRYPT.exact());
    assert!(matches!(
        FSCRYPT.probe(&data),
        Probe::Maybe(reason) if reason == "fscrypt ProtectorData protobuf"
    ));
    assert!(matches!(
        select(&[&FSCRYPT], &data),
        Selection::Unconfirmed(candidates) if candidates.len() == 1
    ));
    let hashes = FSCRYPT.extract(&data).expect("extract fscrypt protector");
    assert_eq!(hashes.len(), 1);
    assert_eq!(render(&hashes, Tool::Hashcat), [expected("fscrypt")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(38900)));
}

#[test]
fn fscrypt_extracts_every_protector_member() {
    let first = std::fs::read(fixture("fscrypt", "sample.bin")).unwrap();
    let second = std::fs::read(fixture("fscrypt", "second.bin")).unwrap();
    let data =
        Artifact::from_bytes("protectors", first).with_member("second", MemorySource::from(second));
    let hashes = FSCRYPT.extract(&data).expect("extract two protectors");
    assert_eq!(hashes.len(), 2);
    let rendered = render(&hashes, Tool::Hashcat);
    assert_eq!(rendered[0], expected("fscrypt"));
    assert!(rendered[1].starts_with("$fscrypt$2*8192*1*"));
}

#[test]
fn fscrypt_rejects_empty_and_malformed_input() {
    assert_eq!(FSCRYPT.probe(&bytes("empty", Vec::new())), Probe::No);
    assert_eq!(
        FSCRYPT.probe(&bytes("text", b"not a protector".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("fscrypt", "sample.bin")).unwrap();
    let truncated = bytes("truncated.bin", data[..20].to_vec());
    assert_eq!(FSCRYPT.probe(&truncated), Probe::No);
    assert!(FSCRYPT.extract(&truncated).is_err());
}

#[test]
fn vmware_probes_and_extracts_the_hashcat_metadata() {
    let data = artifact("vmware-vmx", "sample.vmx");
    assert!(matches!(
        VMWARE.probe(&data),
        Probe::Yes(reason) if reason == "VMware VMX encryption.keySafe"
    ));
    let hashes = VMWARE.extract(&data).expect("extract VMX keySafe");
    assert_eq!(hashes.len(), 1);
    assert_eq!(render(&hashes, Tool::Hashcat), [expected("vmware-vmx")]);
    assert!(hashes[0].modes().contains(&Mode::Hashcat(27400)));
}

#[test]
fn vmware_rejects_empty_plain_and_truncated_input() {
    assert_eq!(VMWARE.probe(&bytes("empty", Vec::new())), Probe::No);
    assert_eq!(
        VMWARE.probe(&bytes("plain", b"displayName = \"fixture\"".to_vec())),
        Probe::No
    );
    let data = std::fs::read(fixture("vmware-vmx", "sample.vmx")).unwrap();
    let truncated = bytes("truncated.vmx", data[..100].to_vec());
    assert_eq!(VMWARE.probe(&truncated), Probe::No);
    assert!(VMWARE.extract(&truncated).is_err());
}

#[test]
fn vmware_rejects_unsupported_key_safe_parameters() {
    let text = std::fs::read_to_string(fixture("vmware-vmx", "sample.vmx")).unwrap();
    let unsupported = bytes(
        "unsupported.vmx",
        text.replace("cipher=AES-256", "cipher=AES-128")
            .into_bytes(),
    );
    assert_eq!(VMWARE.probe(&unsupported), Probe::No);
    assert!(VMWARE.extract(&unsupported).is_err());
}

#[test]
fn probes_distinguish_the_disk_formats() {
    assert!(matches!(
        select(
            &[&FILEVAULT2, &APFS, &SAMSUNG, &VMWARE],
            &artifact("filevault2", "sample.img")
        ),
        Selection::Unique(extractor) if extractor.slug() == "filevault2"
    ));
    assert!(matches!(
        select(&[&FILEVAULT2, &APFS], &artifact("apfs", "sample.img")),
        Selection::Unique(extractor) if extractor.slug() == "apfs"
    ));
    assert!(matches!(
        select(
            &[&FILEVAULT2, &APFS, &SAMSUNG],
            &artifact("android-fde-samsung", "sample.img")
        ),
        Selection::Unique(extractor) if extractor.slug() == "android-fde-samsung"
    ));
    assert!(matches!(
        select(&[&VMWARE], &artifact("vmware-vmx", "sample.vmx")),
        Selection::Unique(extractor) if extractor.slug() == "vmware-vmx"
    ));
    assert!(matches!(
        select(
            &[&FILEVAULT2, &APFS, &SAMSUNG, &FSCRYPT, &VMWARE],
            &bytes("empty", Vec::new())
        ),
        Selection::None
    ));
}
