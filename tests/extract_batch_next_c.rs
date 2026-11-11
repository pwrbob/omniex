//! Extraction for user DPAPI masterkeys, BitLocker recovery keys, AS/400 user
//! profiles, and Lotus Notes/Domino 6/8 user ID files.

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

fn artifact(slug: &str, name: &str) -> Artifact {
    Artifact::from_bytes(
        name,
        std::fs::read(fixture(slug, name)).expect("read fixture"),
    )
}

fn expected(slug: &str, name: &str) -> Vec<String> {
    std::fs::read_to_string(fixture(slug, name))
        .expect("expected hashes")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn rendered(slug: &str, artifact: &Artifact, tool: Tool) -> Vec<String> {
    let extractor = extract::by_slug(slug).expect("registered extractor");
    extractor
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|hash| {
            hash.render(&RenderOptions {
                tool,
                ..RenderOptions::default()
            })
            .expect("render")
        })
        .collect()
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn dpapi_masterkey_file_reports_every_record() {
    let artifact = artifact("dpapi", "masterkey.bin");
    let extractor = extract::by_slug("dpapi").expect("dpapi extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("dpapi", &artifact, Tool::Hashcat),
        expected("dpapi", "masterkey.hash")
    );
    assert_eq!(
        rendered("dpapi", &artifact, Tool::John),
        expected("dpapi", "masterkey.hash")
    );
}

#[test]
fn dpapi_masterkey_file_needs_an_account_sid() {
    let data = std::fs::read(fixture("dpapi", "masterkey.bin")).expect("fixture");
    let sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    let ascii = sid.as_bytes();
    assert!(
        data.windows(ascii.len()).any(|window| window == ascii) || {
            let wide: Vec<u8> = sid.bytes().flat_map(|byte| [byte, 0]).collect();
            data.windows(wide.len()).any(|window| window == wide)
        }
    );
    let wide: Vec<u8> = sid.bytes().flat_map(|byte| [byte, 0]).collect();
    let stripped: Vec<u8> = data
        .windows(wide.len())
        .position(|window| window == wide)
        .map(|position| {
            let mut copy = data.clone();
            copy.drain(position..position + wide.len());
            copy
        })
        .expect("wide SID in fixture");
    let artifact = Artifact::from_bytes("masterkey.bin", stripped);
    let extractor = extract::by_slug("dpapi").expect("dpapi extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Maybe(_)));
    assert!(extractor.extract(&artifact).is_err());
}

#[test]
fn dpapi_masterkey_file_rejects_several_sids() {
    let mut data = std::fs::read(fixture("dpapi", "masterkey.bin")).expect("fixture");
    data.extend_from_slice(b"\nS-1-5-21-9999999999-1111111111-2222222222-1002\n");
    let artifact = Artifact::from_bytes("masterkey.bin", data);
    let extractor = extract::by_slug("dpapi").expect("dpapi extractor");
    assert!(extractor.extract(&artifact).is_err());
}

#[test]
fn dpapi_masterkey_rejects_truncated_and_unrelated_input() {
    let extractor = extract::by_slug("dpapi").expect("dpapi extractor");
    let short = Artifact::from_bytes("short.bin", vec![0u8; 64]);
    assert_eq!(extractor.probe(&short), Probe::No);
    assert!(extractor.extract(&short).is_err());

    let truncated = Artifact::from_bytes(
        "truncated.bin",
        std::fs::read(fixture("dpapi", "masterkey.bin")).expect("fixture")[..160].to_vec(),
    );
    assert_eq!(extractor.probe(&truncated), Probe::No);
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn bitlocker_volume_reports_password_and_recovery_vmks() {
    let artifact = artifact("bitlocker", "recovery.img");
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));

    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 2);
    let hashcat = expected("bitlocker", "recovery.hash");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).expect("render"),
        hashcat[0]
    );
    assert_eq!(
        hashes[1]
            .render(&RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            })
            .expect("render"),
        hashcat[1]
    );
}

fn mbr_disk(volume: &[u8], start_lba: u32) -> Vec<u8> {
    let offset = start_lba as usize * 512;
    let mut disk = vec![0u8; offset + volume.len()];
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    let entry = &mut disk[446..462];
    entry[4] = 0x07;
    entry[8..12].copy_from_slice(&start_lba.to_le_bytes());
    disk[offset..].copy_from_slice(volume);
    disk
}

fn gpt_disk(volume: &[u8], start_lba: u64) -> Vec<u8> {
    let offset = start_lba as usize * 512;
    let mut disk = vec![0u8; offset + volume.len()];
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    let protective = &mut disk[446..462];
    protective[4] = 0xee;
    protective[8..12].copy_from_slice(&1u32.to_le_bytes());

    let header = &mut disk[512..604];
    header[..8].copy_from_slice(b"EFI PART");
    header[72..80].copy_from_slice(&2u64.to_le_bytes());
    header[80..84].copy_from_slice(&1u32.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());

    let entry = &mut disk[1024..1152];
    entry[..16].copy_from_slice(&[0x01; 16]);
    entry[32..40].copy_from_slice(&start_lba.to_le_bytes());
    entry[40..48].copy_from_slice(&(start_lba + 7).to_le_bytes());

    disk[offset..].copy_from_slice(volume);
    disk
}

#[test]
fn bitlocker_finds_volumes_at_partition_starts() {
    let mut volume = std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture");
    volume[13] = 1;
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");

    for (label, disk) in [
        ("mbr.img", mbr_disk(&volume, 8)),
        ("gpt.img", gpt_disk(&volume, 16)),
    ] {
        let artifact = Artifact::from_bytes(label, disk);
        assert!(
            matches!(extractor.probe(&artifact), Probe::Yes(_)),
            "{label}"
        );
        assert_eq!(extractor.extract(&artifact).expect("extract").len(), 2);
    }
}

#[test]
fn bitlocker_accepts_the_recorded_volume_guid() {
    let mut volume = std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture");
    volume[13] = 8;
    volume[0xa0..0xb0].copy_from_slice(&[
        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0,
        0x01,
    ]);
    volume[0xb0..0xb8].copy_from_slice(&0x400u64.to_le_bytes());
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");
    let artifact = Artifact::from_bytes("mbr.img", mbr_disk(&volume, 8));
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(extractor.extract(&artifact).expect("extract").len(), 2);
}

#[test]
fn bitlocker_requires_deep_for_embedded_volumes() {
    let mut volume = std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture");
    volume[13] = 1;
    let mut disk = vec![0u8; 0x2000];
    disk.extend_from_slice(&volume);
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");

    let shallow = Artifact::from_bytes("embedded.img", disk.clone());
    assert_eq!(extractor.probe(&shallow), Probe::No);
    assert!(extractor.extract(&shallow).is_err());

    let deep = Artifact::from_bytes("embedded.img", disk).with_deep(true);
    assert!(matches!(extractor.probe(&deep), Probe::Yes(_)));
    assert_eq!(extractor.extract(&deep).expect("deep extract").len(), 2);
}

#[test]
fn bitlocker_volume_without_crackable_vmk_is_possible() {
    let mut data = std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture");
    for protection_offset in [0x478 + 26, 0x508 + 26] {
        data[protection_offset] = 0x00;
        data[protection_offset + 1] = 0x01;
    }
    let artifact = Artifact::from_bytes("tpm.img", data);
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Maybe(_)));
    assert!(extractor.extract(&artifact).is_err());
}

#[test]
fn bitlocker_rejects_truncated_and_unrelated_input() {
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");
    let unrelated = Artifact::from_bytes("plain.img", b"not a volume".to_vec());
    assert_eq!(extractor.probe(&unrelated), Probe::No);
    assert!(extractor.extract(&unrelated).is_err());

    let truncated = Artifact::from_bytes(
        "truncated.img",
        std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture")[..0x420].to_vec(),
    );
    assert!(matches!(extractor.probe(&truncated), Probe::Maybe(_)));
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn as400_profile_yields_every_verifier() {
    let artifact = artifact("as400", "profile.bin");

    let des = extract::by_slug("as400-des").expect("as400-des extractor");
    assert!(matches!(des.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("as400-des", &artifact, Tool::Hashcat),
        expected("as400", "des.hash")
    );

    let ssha1 = extract::by_slug("as400-ssha1").expect("as400-ssha1 extractor");
    assert!(matches!(ssha1.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("as400-ssha1", &artifact, Tool::Hashcat),
        expected("as400", "ssha1.hash")
    );
}

#[test]
fn embedded_artifacts_are_found_after_other_data() {
    let mut profile = vec![0x7fu8; 512];
    profile.extend(std::fs::read(fixture("as400", "profile.bin")).expect("fixture"));
    let artifact = Artifact::from_bytes("memory.bin", profile);
    let extractor = extract::by_slug("as400-des").expect("as400-des extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("as400-des", &artifact, Tool::Hashcat),
        expected("as400", "des.hash")
    );

    let mut masterkey = vec![0x7fu8; 256];
    masterkey.extend(std::fs::read(fixture("dpapi", "masterkey.bin")).expect("fixture"));
    let artifact = Artifact::from_bytes("collection.bin", masterkey);
    let extractor = extract::by_slug("dpapi").expect("dpapi extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("dpapi", &artifact, Tool::Hashcat),
        expected("dpapi", "masterkey.hash")
    );
}

#[test]
fn bitlocker_scans_every_metadata_block() {
    let mut data = std::fs::read(fixture("bitlocker", "recovery.img")).expect("fixture");
    data.resize(8192, 0);
    let metadata = data[0x400..0x800].to_vec();
    data[0x800..0xC00].copy_from_slice(&metadata);
    data[0x400 + 64] = 0xff;
    data[0x400 + 65] = 0xff;
    data[0x400 + 66] = 0xff;
    data[0x400 + 67] = 0xff;
    data[0xA8..0xB0].copy_from_slice(&0x800u64.to_le_bytes());
    let artifact = Artifact::from_bytes("two-blocks.img", data);
    let extractor = extract::by_slug("bitlocker").expect("bitlocker extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("bitlocker", &artifact, Tool::John),
        expected("bitlocker", "recovery.hash")
    );
}

#[test]
fn as400_profile_rejects_wrapped_and_truncated_input() {
    let mut wrapped = std::fs::read(fixture("as400", "profile.bin")).expect("fixture");
    wrapped[96] = 0x11;
    let artifact = Artifact::from_bytes("wrapped.bin", wrapped);
    for slug in ["as400-des", "as400-ssha1"] {
        let extractor = extract::by_slug(slug).expect("as400 extractor");
        assert_eq!(extractor.probe(&artifact), Probe::No, "{slug}");
        assert!(extractor.extract(&artifact).is_err(), "{slug}");
    }

    let truncated = Artifact::from_bytes(
        "truncated.bin",
        std::fs::read(fixture("as400", "profile.bin")).expect("fixture")[..40].to_vec(),
    );
    let extractor = extract::by_slug("as400-des").expect("as400-des extractor");
    assert_eq!(extractor.probe(&truncated), Probe::No);
    assert!(extractor.extract(&truncated).is_err());
}

#[test]
fn lotus_notes_id_file_yields_its_digests() {
    let artifact = artifact("lotus-notes", "user.id");
    let extractor = extract::by_slug("lotus-notes").expect("lotus extractor");
    assert!(matches!(extractor.probe(&artifact), Probe::Yes(_)));
    assert_eq!(
        rendered("lotus-notes", &artifact, Tool::Hashcat),
        expected("lotus-notes", "expected.hash")
    );
}

#[test]
fn lotus_notes_rejects_unrelated_input() {
    let extractor = extract::by_slug("lotus-notes").expect("lotus extractor");
    for bytes in [
        b"hello world".to_vec(),
        b"(GDJ0nDZI8l8RJzlRbem!)".to_vec(),
        b"(GDJ0nDZI8l8RJzlRbemgg)".to_vec(),
        b"(GDJ0nDZI8l8RJzlRbemg".to_vec(),
    ] {
        let artifact = Artifact::from_bytes("plain.bin", bytes);
        assert_eq!(extractor.probe(&artifact), Probe::No);
        assert!(extractor.extract(&artifact).is_err());
    }
}

#[test]
fn every_new_extractor_rejects_empty_input() {
    for slug in [
        "dpapi",
        "bitlocker",
        "as400-des",
        "as400-ssha1",
        "lotus-notes",
    ] {
        let extractor = extract::by_slug(slug).expect("registered extractor");
        let empty = Artifact::from_bytes("empty", Vec::new());
        assert_eq!(extractor.probe(&empty), Probe::No, "{slug}");
        assert!(extractor.extract(&empty).is_err(), "{slug}");
    }
}

#[test]
fn cli_extracts_explicit_types() {
    for (slug, path, format, count) in [
        ("dpapi", fixture("dpapi", "masterkey.bin"), "hashcat", 3),
        ("bitlocker", fixture("bitlocker", "recovery.img"), "john", 2),
        ("as400-des", fixture("as400", "profile.bin"), "hashcat", 2),
        ("as400-ssha1", fixture("as400", "profile.bin"), "hashcat", 1),
        (
            "lotus-notes",
            fixture("lotus-notes", "user.id"),
            "hashcat",
            2,
        ),
    ] {
        let output = omniex()
            .args(["extract", "--type", slug, "--format", format])
            .arg(&path)
            .output()
            .expect("run omniex");
        assert!(output.status.success(), "{slug}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).lines().count(),
            count,
            "{slug}"
        );
    }
}
