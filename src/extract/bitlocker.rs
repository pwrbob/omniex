//! BitLocker FVE volume metadata, VMK material, and recovery-key records.

use super::container::Window;
use super::{Artifact, ExtractError, Extracted, Extractor, OptionSpec, Probe, ReadAt, container};
use crate::types::BitLocker;
use crate::{HashType, HashValue};

const OPTIONS: &[OptionSpec] = &[OptionSpec::flag(
    "deep",
    "scan for volumes that are not at a partition start",
)];

const BITLOCKER: &[u8] = b"-FVE-FS-";
const BITLOCKER_TO_GO: &[u8] = b"MSWIN4.1";
const METADATA_HEADER: usize = 112;
const MAX_METADATA: usize = 1 << 20;
const ITERATIONS: u32 = 0x10_0000;
const PROTECTION_RECOVERY: u16 = 0x800;
const PROTECTION_PASSWORD: u16 = 0x2000;
const KIND_PASSWORD: u8 = 1;
const KIND_RECOVERY: u8 = 3;

struct Recovery {
    kind: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    data: [u8; 60],
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

const SECTOR_SIZE: u64 = 512;
const MBR_PARTITION_TABLE: usize = 446;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const MAX_GPT_ENTRIES: u32 = 128;
const MAX_GPT_ENTRY_SIZE: u32 = 4096;
const MAX_GPT_TABLE: usize = 1 << 20;

const BITLOCKER_GUIDS: [[u8; 16]; 2] = [
    [
        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0,
        0x01,
    ],
    [
        0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae,
        0xd8,
    ],
];

fn known_volume_guid(source: &dyn ReadAt, offset: u64, guid_offset: usize) -> bool {
    let mut guid = [0u8; 16];
    source
        .read_exact_at(offset.saturating_add(guid_offset as u64), &mut guid)
        .is_ok()
        && BITLOCKER_GUIDS.contains(&guid)
}

fn volume_signature(source: &dyn ReadAt, offset: u64) -> Option<usize> {
    let mut header = [0u8; 16];
    source.read_exact_at(offset, &mut header).ok()?;
    if &header[3..11] == BITLOCKER {
        (offset == 0 || matches!(header[13], 1 | 2) || known_volume_guid(source, offset, 0xa0))
            .then_some(0xa0)
    } else if &header[3..11] == BITLOCKER_TO_GO {
        Some(0x1a8)
    } else {
        None
    }
}

fn gpt_partition_offsets(source: &dyn ReadAt) -> Vec<u64> {
    let mut header = [0u8; 92];
    if source.read_exact_at(SECTOR_SIZE, &mut header).is_err()
        || &header[..GPT_SIGNATURE.len()] != GPT_SIGNATURE
    {
        return Vec::new();
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap_or_default());
    let entries = u32::from_le_bytes(header[80..84].try_into().unwrap_or_default());
    let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap_or_default());
    if entries == 0
        || entries > MAX_GPT_ENTRIES
        || !(128..=MAX_GPT_ENTRY_SIZE).contains(&entry_size)
    {
        return Vec::new();
    }
    let total = usize::try_from(entries)
        .ok()
        .and_then(|count| {
            usize::try_from(entry_size)
                .ok()
                .and_then(|size| count.checked_mul(size))
        })
        .unwrap_or(0);
    if total == 0 || total > MAX_GPT_TABLE {
        return Vec::new();
    }
    let mut table = vec![0u8; total];
    if source
        .read_exact_at(entries_lba.saturating_mul(SECTOR_SIZE), &mut table)
        .is_err()
    {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    for entry in table.chunks_exact(usize::from(entry_size as u16)) {
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let start = u64::from_le_bytes(entry[32..40].try_into().unwrap_or_default());
        if start != 0 {
            offsets.push(start.saturating_mul(SECTOR_SIZE));
        }
    }
    offsets
}

fn partition_offsets(source: &dyn ReadAt) -> Vec<u64> {
    let mut mbr = [0u8; 512];
    if source.read_exact_at(0, &mut mbr).is_err() || mbr[510..512] != [0x55, 0xaa] {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    let mut gpt = false;
    for entry in mbr[MBR_PARTITION_TABLE..MBR_PARTITION_TABLE + 64].chunks_exact(16) {
        let kind = entry[4];
        let start = u64::from(u32::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11],
        ]));
        if kind == 0xee {
            gpt = true;
            continue;
        }
        if kind != 0 && start != 0 {
            offsets.push(start.saturating_mul(SECTOR_SIZE));
        }
    }
    if gpt {
        offsets.extend(gpt_partition_offsets(source));
    }
    offsets
}

fn candidate_offsets(source: &dyn ReadAt) -> Vec<u64> {
    let mut offsets = vec![0];
    offsets.extend(partition_offsets(source));
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn volumes<'a>(source: &'a dyn ReadAt) -> Vec<(Window<'a>, usize)> {
    let mut results = Vec::new();
    for offset in candidate_offsets(source) {
        if offset >= source.len() {
            continue;
        }
        if let Some(guid_offset) = volume_signature(source, offset) {
            results.push((
                Window::new(source, offset, source.len() - offset),
                guid_offset,
            ));
            if results.len() >= 16 {
                break;
            }
        }
    }
    results
}

fn volumes_deep<'a>(source: &'a container::Container<'a>) -> Vec<(Window<'a>, usize)> {
    const WINDOW: usize = 1 << 20;
    const OVERLAP: usize = 16;
    let mut results = Vec::new();
    let mut buffer = vec![0u8; WINDOW + OVERLAP];
    for (start, len) in source.data_ranges() {
        let end = start.saturating_add(len);
        let mut position = start;
        while position < end {
            let available = usize::try_from(end - position)
                .unwrap_or(buffer.len())
                .min(buffer.len());
            let read = source
                .read_at(position, &mut buffer[..available])
                .unwrap_or(0);
            if read == 0 {
                break;
            }
            for signature in [BITLOCKER, BITLOCKER_TO_GO] {
                let guid_offset = if signature == BITLOCKER { 0xa0 } else { 0x1a8 };
                for index in memchr::memmem::find_iter(&buffer[..read], signature) {
                    let signature_offset = position + index as u64;
                    if signature == BITLOCKER {
                        let version = buffer.get(index + 10).copied().unwrap_or(0);
                        if !matches!(version, 1 | 2) && signature_offset != 3 {
                            continue;
                        }
                    }
                    let volume_offset = signature_offset.saturating_sub(3);
                    results.push((
                        Window::new(source, volume_offset, source.len() - volume_offset),
                        guid_offset,
                    ));
                    if results.len() >= 16 {
                        return results;
                    }
                }
            }
            if read <= OVERLAP {
                break;
            }
            position += (read - OVERLAP) as u64;
        }
    }
    results
}

fn scan_vmk(source: &dyn ReadAt) -> Vec<Recovery> {
    const VMK_ENTRY: [u8; 4] = [0x02, 0x00, 0x08, 0x00];
    let mut window = vec![0u8; 0x1000];
    let read = source.read_at(0, &mut window).unwrap_or(0);
    let mut found = Vec::new();
    let mut start = 0;
    while let Some(offset) = window[..read]
        .windows(4)
        .skip(start)
        .position(|candidate| candidate == VMK_ENTRY)
    {
        let entry = start + offset;
        start = entry + 1;
        let mut block = vec![0u8; 256];
        if source.read_exact_at(entry as u64, &mut block).is_err() {
            continue;
        }
        let protection = u16::from_le_bytes([block[32], block[33]]);
        let mut candidates = Vec::new();
        match protection {
            PROTECTION_PASSWORD => {
                if block[32 + 113..32 + 115] == [0x00, 0x05] {
                    candidates.push((32 + 14, 32 + 118));
                }
            }
            PROTECTION_RECOVERY => {
                for salt in [32 + 14, 32 + 34] {
                    let aes = salt + 16 + 147;
                    if block.get(aes..aes + 2) == Some(&[0x00, 0x05]) {
                        candidates.push((salt, aes + 3));
                    }
                }
            }
            _ => {}
        }
        for (salt, nonce) in candidates {
            let mut recovery = Recovery {
                kind: if protection == PROTECTION_PASSWORD {
                    KIND_PASSWORD
                } else {
                    KIND_RECOVERY
                },
                salt: [0; 16],
                nonce: [0; 12],
                data: [0; 60],
            };
            if block.get(salt..salt + 16).is_none() || block.get(nonce..nonce + 72).is_none() {
                continue;
            }
            recovery.salt.copy_from_slice(&block[salt..salt + 16]);
            recovery.nonce.copy_from_slice(&block[nonce..nonce + 12]);
            recovery
                .data
                .copy_from_slice(&block[nonce + 12..nonce + 72]);
            found.push(recovery);
        }
    }
    found
}

fn stretched_salt(entry: &[u8]) -> Option<[u8; 16]> {
    let salt = entry.get(4..20)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(salt);
    Some(out)
}

fn aes_ccm(entry: &[u8]) -> Option<([u8; 12], [u8; 60])> {
    let nonce = entry.get(0..12)?;
    let payload = entry.get(12..72)?;
    let mut nonce_out = [0u8; 12];
    nonce_out.copy_from_slice(nonce);
    let mut data = [0u8; 60];
    data.copy_from_slice(payload);
    Some((nonce_out, data))
}

fn parse_vmk(entry: &[u8], found: &mut Vec<Recovery>) -> Result<(), ExtractError> {
    let protection = u16_at(entry, 26)
        .ok_or_else(|| ExtractError::Invalid("truncated BitLocker VMK entry".to_owned()))?;
    let kind = match protection {
        PROTECTION_PASSWORD => KIND_PASSWORD,
        PROTECTION_RECOVERY => KIND_RECOVERY,
        _ => return Ok(()),
    };

    let mut salt = None;
    let mut encrypted = Vec::new();
    let mut position = 28;
    while position < entry.len() {
        let size =
            usize::from(u16_at(entry, position).ok_or_else(|| {
                ExtractError::Invalid("truncated BitLocker VMK property".to_owned())
            })?);
        if size < 8 || position + size > entry.len() {
            return Err(ExtractError::Invalid(
                "invalid BitLocker VMK property size".to_owned(),
            ));
        }
        let value_type = u16_at(entry, position + 4).unwrap_or_default();
        let value = &entry[position + 8..position + size];
        position += size;

        match value_type {
            0x3 => {
                if let Some(candidate) = stretched_salt(value) {
                    salt = Some(candidate);
                }
            }
            0x5 => {
                if let Some(candidate) = aes_ccm(value) {
                    encrypted.push(candidate);
                }
            }
            _ => {}
        }
    }

    let Some(salt) = salt else {
        return Err(ExtractError::Invalid(
            "BitLocker VMK has no stretch key salt".to_owned(),
        ));
    };
    if encrypted.is_empty() {
        return Err(ExtractError::Invalid(
            "BitLocker VMK has no encrypted key material".to_owned(),
        ));
    }
    for (nonce, data) in encrypted {
        found.push(Recovery {
            kind,
            salt,
            nonce,
            data,
        });
    }
    Ok(())
}

fn parse_block(block: &[u8]) -> Result<Vec<Recovery>, ExtractError> {
    let metadata_size =
        usize::try_from(u32_at(block, 64).ok_or_else(|| {
            ExtractError::Invalid("truncated BitLocker metadata header".to_owned())
        })?)
        .map_err(|_| ExtractError::Invalid("invalid BitLocker metadata size".to_owned()))?;
    if metadata_size < METADATA_HEADER || metadata_size > block.len() {
        return Err(ExtractError::Invalid(
            "invalid BitLocker metadata size".to_owned(),
        ));
    }

    let mut found = Vec::new();
    let mut position = METADATA_HEADER;
    while position < metadata_size {
        let size = usize::from(u16_at(block, position).ok_or_else(|| {
            ExtractError::Invalid("truncated BitLocker metadata entry".to_owned())
        })?);
        if size < 8 {
            return Err(ExtractError::Invalid(
                "invalid BitLocker metadata entry size".to_owned(),
            ));
        }
        if position + size > metadata_size {
            break;
        }
        let value_type = u16_at(block, position + 4).unwrap_or_default();
        let value = &block[position + 8..position + size];
        position += size;

        if value_type == 0x8 {
            parse_vmk(value, &mut found)?;
        }
    }
    Ok(found)
}

fn metadata_offsets(source: &dyn ReadAt, guid_offset: usize) -> Result<Vec<u64>, ExtractError> {
    let mut header = [0u8; 24];
    source
        .read_exact_at(guid_offset as u64, &mut header)
        .map_err(|_| ExtractError::Invalid("truncated BitLocker volume header".to_owned()))?;
    let mut offsets = Vec::new();
    for index in 0..3 {
        let offset = u64_at(&header, index * 8)
            .ok_or_else(|| ExtractError::Invalid("truncated BitLocker header".to_owned()))?;
        if offset != 0 {
            offsets.push(offset);
        }
    }
    Ok(offsets)
}

fn read_metadata(source: &dyn ReadAt, offset: u64) -> Result<Vec<u8>, ExtractError> {
    let mut header = [0u8; METADATA_HEADER];
    source
        .read_exact_at(offset, &mut header)
        .map_err(|_| ExtractError::Invalid("truncated BitLocker metadata block".to_owned()))?;
    let size =
        usize::try_from(u32_at(&header, 64).ok_or_else(|| {
            ExtractError::Invalid("truncated BitLocker metadata header".to_owned())
        })?)
        .map_err(|_| ExtractError::Invalid("invalid BitLocker metadata size".to_owned()))?;
    if !(METADATA_HEADER..=MAX_METADATA).contains(&size) {
        return Err(ExtractError::Invalid(
            "invalid BitLocker metadata size".to_owned(),
        ));
    }
    let mut block = vec![0u8; size];
    source
        .read_exact_at(offset, &mut block)
        .map_err(|_| ExtractError::Invalid("truncated BitLocker metadata block".to_owned()))?;
    Ok(block)
}

fn candidate_volumes<'a>(
    container: &'a container::Container<'a>,
    deep: bool,
) -> Vec<(Window<'a>, usize)> {
    let structured = volumes(container);
    if deep && structured.is_empty() {
        volumes_deep(container)
    } else {
        structured
    }
}

fn extract(artifact: &Artifact) -> Result<Vec<BitLocker>, ExtractError> {
    let container = container::Container::open(artifact)?;
    let candidates = candidate_volumes(&container, artifact.deep());
    if candidates.is_empty() {
        return Err(ExtractError::Unsupported(
            "not a BitLocker volume".to_owned(),
        ));
    }

    let mut recoveries = Vec::new();
    let mut parsed = 0;
    let mut last_error = None;
    for (source, guid_offset) in &candidates {
        let offsets = match metadata_offsets(source, *guid_offset) {
            Ok(offsets) if !offsets.is_empty() => offsets,
            Ok(_) => continue,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        for offset in offsets {
            match read_metadata(source, offset) {
                Ok(block) => match parse_block(&block) {
                    Ok(mut found) => {
                        parsed += 1;
                        recoveries.append(&mut found);
                    }
                    Err(error) => last_error = Some(error),
                },
                Err(error) => last_error = Some(error),
            }
        }
        if !recoveries.is_empty() {
            break;
        }
    }
    if recoveries.is_empty() {
        for (source, _) in &candidates {
            recoveries.extend(scan_vmk(source));
        }
    }

    if parsed == 0 && recoveries.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            ExtractError::Invalid("malformed BitLocker metadata block".to_owned())
        }));
    }
    if recoveries.is_empty() {
        return Err(ExtractError::Unsupported(
            "BitLocker volume has no password- or recovery-protected VMK".to_owned(),
        ));
    }

    let mut hashes = Vec::new();
    for recovery in recoveries {
        let hash = BitLocker {
            kind: recovery.kind,
            salt_size: 16,
            salt: recovery.salt,
            iterations: ITERATIONS,
            nonce_size: 12,
            nonce: recovery.nonce,
            data_size: 60,
            data: recovery.data,
        };
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    Ok(hashes)
}

/// Extractor for BitLocker volume metadata and VMK material.
///
/// Password-protected VMKs render with verification type `1`. Recovery-key
/// protected VMKs render with type `3`, which hashcat mode `22100` rejects but
/// John's `BitLocker` format accepts.
pub struct BitlockerExtractor;

impl Extractor for BitlockerExtractor {
    fn slug(&self) -> &'static str {
        BitLocker::SLUG
    }

    fn options(&self) -> &'static [OptionSpec] {
        OPTIONS
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let Ok(container) = container::Container::open(artifact) else {
            return Probe::No;
        };
        if candidate_volumes(&container, artifact.deep()).is_empty() {
            return Probe::No;
        }
        match extract(artifact) {
            Ok(_) => Probe::yes("BitLocker FVE volume metadata"),
            Err(ExtractError::Unsupported(_)) => {
                Probe::maybe("BitLocker volume without a password- or recovery-protected VMK")
            }
            Err(_) => Probe::maybe("malformed BitLocker volume metadata"),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
