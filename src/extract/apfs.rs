//! APFS container and volume keybag extraction.

use std::io;

use byteorder::{ByteOrder, LittleEndian};

use super::filevault2::{read_exact, xts_decrypt_sectors};
use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::types::Apfs;
use omniex::{HashType, HashValue};

pub struct ApfsExtractor;

const CHUNK_SIZE: usize = 1 << 20;
const BLOCK_MAGIC: &[u8] = b"NXSB";
const CONTAINER_KEYBAG: &[u8] = b"syek";
const VOLUME_KEYBAG: &[u8] = b"scer";
const VOLUME_UNLOCK_TAG: u16 = 3;
const RECOVERY_UUIDS: [[u8; 16]; 2] = [
    [
        0xeb, 0xc6, 0xc0, 0x64, 0x00, 0x00, 0x11, 0xaa, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec,
        0xac,
    ],
    [
        0xec, 0x1c, 0x2a, 0xd9, 0xb6, 0x18, 0x4e, 0xd6, 0xbd, 0x8d, 0x50, 0xf3, 0x61, 0xc2, 0x75,
        0x07,
    ],
];

struct Entry {
    uuid: [u8; 16],
    tag: u16,
    data: Vec<u8>,
}

fn candidates(source: &dyn ReadAt) -> io::Result<Vec<u64>> {
    let mut offsets = Vec::new();
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut base = 0u64;
    while base < source.len() {
        let read = source.read_at(base, &mut chunk)?;
        if read < 4 {
            break;
        }
        for index in 0..read - 3 {
            if &chunk[index..index + 4] != BLOCK_MAGIC {
                continue;
            }
            let signature = base + index as u64;
            if signature < 0x20 {
                continue;
            }
            offsets.push(signature - 0x20);
        }
        base += read as u64;
    }
    Ok(offsets)
}

fn entries(raw: &[u8], count: u32) -> Result<Vec<Entry>, ExtractError> {
    let mut result = Vec::new();
    let mut position = 0usize;
    for _ in 0..count {
        let header = raw
            .get(position..position + 0x18)
            .ok_or_else(|| ExtractError::Invalid("truncated APFS keybag entry".to_owned()))?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&header[..16]);
        let tag = LittleEndian::read_u16(&header[16..18]);
        let length = usize::from(LittleEndian::read_u16(&header[18..20]));
        let start = position + 0x18;
        let data = raw
            .get(start..start + length)
            .ok_or_else(|| ExtractError::Invalid("truncated APFS keybag value".to_owned()))?;
        result.push(Entry {
            uuid,
            tag,
            data: data.to_vec(),
        });
        position = (start + length).div_ceil(16) * 16;
    }
    Ok(result)
}

fn keybag(data: &[u8], expected: &[u8]) -> Result<Vec<Entry>, ExtractError> {
    if data.len() < 0x30 {
        return Err(ExtractError::Invalid("truncated APFS keybag".to_owned()));
    }
    if &data[0x18..0x1c] != expected {
        return Err(ExtractError::Unsupported(
            "unexpected APFS keybag object type".to_owned(),
        ));
    }
    let count = u32::from(LittleEndian::read_u16(&data[0x22..0x24]));
    let size = usize::try_from(LittleEndian::read_u32(&data[0x24..0x28]))
        .map_err(|_| ExtractError::Invalid("invalid APFS keybag size".to_owned()))?;
    let body = data
        .get(0x30..0x30 + size)
        .ok_or_else(|| ExtractError::Invalid("truncated APFS keybag body".to_owned()))?;
    entries(body, count)
}

fn little_number(value: &[u8]) -> u32 {
    let mut result = 0u64;
    for (index, byte) in value.iter().enumerate().take(8) {
        result |= u64::from(*byte) << (8 * index);
    }
    u32::try_from(result).unwrap_or(u32::MAX)
}

fn wrapped_user(value: &[u8]) -> Result<Option<Apfs>, ExtractError> {
    let mut position = 0;
    let mut wrapped = None;
    let mut salt = None;
    let mut iterations = None;
    let mut kind = None;
    for expected in [0x80u8, 0x81, 0x82, 0x83, 0x84, 0x85] {
        let tag = *value
            .get(position)
            .ok_or_else(|| ExtractError::Invalid("truncated APFS wrapped KEK".to_owned()))?;
        let length = usize::from(
            *value
                .get(position + 1)
                .ok_or_else(|| ExtractError::Invalid("truncated APFS wrapped KEK".to_owned()))?,
        );
        if tag != expected {
            return Err(ExtractError::Invalid(
                "unexpected APFS wrapped KEK tag".to_owned(),
            ));
        }
        let chunk = value
            .get(position + 2..position + 2 + length)
            .ok_or_else(|| ExtractError::Invalid("truncated APFS wrapped KEK".to_owned()))?;
        match tag {
            0x82 => kind = Some(chunk),
            0x83 => wrapped = Some(chunk),
            0x84 => iterations = Some(chunk),
            0x85 => salt = Some(chunk),
            _ => {}
        }
        position += 2 + length;
    }
    let kind = kind.ok_or_else(|| ExtractError::Invalid("missing APFS cipher type".to_owned()))?;
    if kind.len() < 4 {
        return Err(ExtractError::Invalid("invalid APFS cipher type".to_owned()));
    }
    if !matches!(LittleEndian::read_u32(kind), 16 | 0) {
        return Ok(None);
    }
    let wrapped =
        wrapped.ok_or_else(|| ExtractError::Invalid("missing APFS wrapped key".to_owned()))?;
    let salt = salt.ok_or_else(|| ExtractError::Invalid("missing APFS salt".to_owned()))?;
    let iterations =
        iterations.ok_or_else(|| ExtractError::Invalid("missing APFS iterations".to_owned()))?;
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid APFS salt length".to_owned()))?;
    let wrapped_key: [u8; 40] = wrapped
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid APFS wrapped key length".to_owned()))?;
    Ok(Some(Apfs {
        primary_key: 2,
        salt,
        iterations: little_number(iterations),
        wrapped_key,
    }))
}

fn volume_users(data: &[u8]) -> Result<Vec<Apfs>, ExtractError> {
    let mut hashes = Vec::new();
    for entry in keybag(data, VOLUME_KEYBAG)? {
        if entry.tag != VOLUME_UNLOCK_TAG || RECOVERY_UUIDS.contains(&entry.uuid) {
            continue;
        }
        let Some(inner) = entry.data.get(1) else {
            continue;
        };
        if entry.data[0] != 0x30 {
            continue;
        }
        let packed = entry
            .data
            .get(2..2 + usize::from(*inner))
            .ok_or_else(|| ExtractError::Invalid("truncated APFS packed value".to_owned()))?;
        let mut position = 1;
        for _ in 0..4 {
            let Some(tag) = packed.get(position) else {
                break;
            };
            let Some(length) = packed.get(position + 1) else {
                break;
            };
            let start = position + 2;
            let chunk = packed
                .get(start..start + usize::from(*length))
                .ok_or_else(|| ExtractError::Invalid("truncated APFS packed object".to_owned()))?;
            if *tag == 0xa3 {
                if let Some(hash) = wrapped_user(chunk)? {
                    hashes.push(hash);
                }
            }
            position = start + usize::from(*length);
        }
    }
    Ok(hashes)
}

fn container(source: &dyn ReadAt, start: u64) -> Result<Vec<Apfs>, ExtractError> {
    let header = read_exact(source, start, 0x568, "APFS container superblock")?;
    if &header[0x20..0x24] != BLOCK_MAGIC {
        return Err(ExtractError::Unsupported(
            "not an APFS container superblock".to_owned(),
        ));
    }
    let block_size = usize::try_from(LittleEndian::read_u32(&header[0x24..0x28]))
        .map_err(|_| ExtractError::Invalid("invalid APFS block size".to_owned()))?;
    if !block_size.is_power_of_two() || !(512..=65536).contains(&block_size) {
        return Err(ExtractError::Unsupported(
            "unsupported APFS block size".to_owned(),
        ));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&header[0x20 + 0x28..0x20 + 0x38]);
    if uuid == [0; 16] {
        return Err(ExtractError::Invalid(
            "missing APFS container UUID".to_owned(),
        ));
    }
    let locker = LittleEndian::read_u64(&header[0x20 + 0x4f0..0x20 + 0x4f8]);
    if locker == 0 {
        return Err(ExtractError::Unsupported(
            "APFS container has no keybag".to_owned(),
        ));
    }
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&uuid);
    key[16..].copy_from_slice(&uuid);

    let offset = start
        .checked_add(locker * block_size as u64)
        .ok_or_else(|| ExtractError::Invalid("APFS keybag offset overflow".to_owned()))?;
    let mut primary = read_exact(source, offset, block_size, "APFS container keybag")?;
    xts_decrypt_sectors(&key, locker * (block_size as u64 / 512), &mut primary, 512)?;
    let volumes = keybag(&primary, CONTAINER_KEYBAG)?;

    let mut hashes = Vec::new();
    for entry in volumes {
        if entry.tag != VOLUME_UNLOCK_TAG || entry.data.len() < 4 {
            continue;
        }
        let address = u64::from(LittleEndian::read_u32(&entry.data[..4]));
        if address == 0 {
            continue;
        }
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&entry.uuid);
        key[16..].copy_from_slice(&entry.uuid);
        let offset = start
            .checked_add(address * block_size as u64)
            .ok_or_else(|| ExtractError::Invalid("APFS keybag offset overflow".to_owned()))?;
        let mut data = read_exact(source, offset, block_size, "APFS volume keybag")?;
        xts_decrypt_sectors(&key, address * (block_size as u64 / 512), &mut data, 512)?;
        if &data[0x18..0x1c] != VOLUME_KEYBAG {
            continue;
        }
        hashes.extend(volume_users(&data)?);
    }
    Ok(hashes)
}

fn extract_all(artifact: &Artifact) -> Result<Vec<Apfs>, ExtractError> {
    let source = artifact.primary();
    let offsets = candidates(source).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut hashes = Vec::new();
    for offset in offsets {
        match container(source, offset) {
            Ok(found) => hashes.extend(found),
            Err(ExtractError::Unsupported(_)) => {}
            Err(error) => return Err(error),
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no APFS volume password hashes found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for ApfsExtractor {
    fn slug(&self) -> &'static str {
        Apfs::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match extract_all(artifact) {
            Ok(_) => Probe::yes("APFS container keybag"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract_all(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
