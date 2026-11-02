//! Armory wallet extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Armory;
use crate::{HashType, HashValue};

pub struct ArmoryExtractor;

const MAGIC: &[u8] = b"\xbaWALLET\x00";
const HEADER_LEN: usize = 2107;
const ADDRESS_LEN: usize = 237;

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn le_i64(data: &[u8], offset: usize) -> Option<i64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(i64::from_le_bytes(bytes.try_into().ok()?))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

struct Kdf {
    memory: u64,
    iterations: u32,
    salt: [u8; 32],
}

fn kdf(data: &[u8]) -> Result<Kdf, ExtractError> {
    let memory = le_u64(data, 334)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory KDF".to_owned()))?;
    let iterations = le_u32(data, 342)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory KDF".to_owned()))?;
    let salt = data
        .get(346..378)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory KDF salt".to_owned()))?;
    if memory == 0 || iterations == 0 {
        return Err(ExtractError::Unsupported(
            "Armory wallet has no key derivation parameters".to_owned(),
        ));
    }
    Ok(Kdf {
        memory,
        iterations,
        salt: salt.try_into().expect("32-byte salt"),
    })
}

fn address(data: &[u8], offset: usize) -> Result<Option<Vec<u8>>, ExtractError> {
    let raw = data
        .get(offset..offset + ADDRESS_LEN)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory address".to_owned()))?;
    let flags = le_u64(raw, 28)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory address flags".to_owned()))?;
    let chain_index = le_i64(raw, 72)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory chain index".to_owned()))?;
    let has_private = flags & 1 != 0;
    let encrypted = flags & 4 != 0;
    let pending = flags & 8 != 0;
    if !has_private || !encrypted || pending || chain_index == -1 {
        return Ok(None);
    }
    let iv = raw
        .get(88..104)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory IV".to_owned()))?;
    let private = raw
        .get(108..140)
        .ok_or_else(|| ExtractError::Invalid("truncated Armory private key".to_owned()))?;
    if iv.iter().all(|byte| *byte == 0) || private.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    Ok(Some(raw.to_vec()))
}

fn parse(artifact: &Artifact) -> Result<Vec<Armory>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ExtractError::Unsupported(
            "not an Armory wallet".to_owned(),
        ));
    }
    if data.len() < HEADER_LEN {
        return Err(ExtractError::Invalid("truncated Armory wallet".to_owned()));
    }
    let kdf = kdf(&data)?;
    let mut hashes = Vec::new();
    let mut offset = HEADER_LEN;
    while offset < data.len() {
        let kind = data[offset];
        offset += 1;
        match kind {
            0 => {
                let hash = data
                    .get(offset..offset + 20)
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory entry".to_owned()))?;
                let raw = address(&data, offset + 20)?;
                if let Some(raw) = raw {
                    let iv = &raw[88..104];
                    let private = &raw[108..140];
                    let mut payload = Vec::with_capacity(3 + 20 + 32 + 16 + 8 + 4 + 32 + 4);
                    payload.extend_from_slice(b"ar:");
                    payload.extend_from_slice(hash);
                    payload.extend_from_slice(private);
                    payload.extend_from_slice(iv);
                    payload.extend_from_slice(&kdf.memory.to_le_bytes());
                    payload.extend_from_slice(&kdf.iterations.to_le_bytes());
                    payload.extend_from_slice(&kdf.salt);
                    let crc = crc32(&payload);
                    payload.extend_from_slice(&crc.to_le_bytes());
                    hashes.push(Armory { data: payload });
                }
                offset += 20 + ADDRESS_LEN;
            }
            1 => {
                offset = offset
                    .checked_add(20)
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory comment".to_owned()))?;
                let length = usize::from(
                    data.get(offset..offset + 2)
                        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                        .ok_or_else(|| {
                            ExtractError::Invalid("truncated Armory comment".to_owned())
                        })?,
                );
                offset = offset
                    .checked_add(2 + length)
                    .filter(|offset| *offset <= data.len())
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory comment".to_owned()))?;
            }
            2 => {
                offset = offset
                    .checked_add(32)
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory comment".to_owned()))?;
                let length = usize::from(
                    data.get(offset..offset + 2)
                        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                        .ok_or_else(|| {
                            ExtractError::Invalid("truncated Armory comment".to_owned())
                        })?,
                );
                offset = offset
                    .checked_add(2 + length)
                    .filter(|offset| *offset <= data.len())
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory comment".to_owned()))?;
            }
            4 => {
                let length = usize::from(
                    data.get(offset..offset + 2)
                        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                        .ok_or_else(|| {
                            ExtractError::Invalid("truncated Armory deletion".to_owned())
                        })?,
                );
                offset = offset
                    .checked_add(2 + length)
                    .filter(|offset| *offset <= data.len())
                    .ok_or_else(|| ExtractError::Invalid("truncated Armory deletion".to_owned()))?;
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "unsupported Armory wallet entry".to_owned(),
                ));
            }
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "Armory wallet has no encrypted private keys".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for ArmoryExtractor {
    fn slug(&self) -> &'static str {
        Armory::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Armory wallet header and encrypted keys"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
