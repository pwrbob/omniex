//! BitLocker FVE volume metadata and recovery key material.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::BitLocker;
use crate::{HashType, HashValue};

const BITLOCKER: &[u8] = b"-FVE-FS-";
const BITLOCKER_TO_GO: &[u8] = b"MSWIN4.1";
const BLOCK_SIZE: usize = 2048;
const ITERATIONS: u32 = 0x10_0000;
const PASSWORD_VMK: u16 = 0x2000;

struct Recovery {
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

fn signature(source: &dyn ReadAt) -> Option<usize> {
    let mut header = [0u8; 11];
    source.read_exact_at(0, &mut header).ok()?;
    if &header[3..] == BITLOCKER {
        Some(0xa0)
    } else if &header[3..] == BITLOCKER_TO_GO {
        Some(0x1a8)
    } else {
        None
    }
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

fn parse_vmk(entry: &[u8], salt: &mut Option<[u8; 16]>, found: &mut Vec<Recovery>) -> Result<(), ExtractError> {
    let protection = u16_at(entry, 26)
        .ok_or_else(|| ExtractError::Invalid("truncated BitLocker VMK entry".to_owned()))?;
    if protection != PASSWORD_VMK {
        return Ok(());
    }

    let mut position = 28;
    while position < entry.len() {
        let size = usize::from(u16_at(entry, position).ok_or_else(|| {
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
                    *salt = Some(candidate);
                }
            }
            0x5 => {
                if let (Some(current), Some((nonce, data))) = (*salt, aes_ccm(value)) {
                    found.push(Recovery {
                        salt: current,
                        nonce,
                        data,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_block(block: &[u8]) -> Result<Vec<Recovery>, ExtractError> {
    let metadata_size = usize::try_from(u32_at(block, 64).ok_or_else(|| {
        ExtractError::Invalid("truncated BitLocker metadata header".to_owned())
    })?)
    .map_err(|_| ExtractError::Invalid("invalid BitLocker metadata size".to_owned()))?;
    if metadata_size < 112 || metadata_size > block.len() {
        return Err(ExtractError::Invalid(
            "invalid BitLocker metadata size".to_owned(),
        ));
    }

    let mut salt = None;
    let mut found = Vec::new();
    let mut position = 112;
    while position < metadata_size {
        let size = usize::from(u16_at(block, position).ok_or_else(|| {
            ExtractError::Invalid("truncated BitLocker metadata entry".to_owned())
        })?);
        if size < 8 || position + size > block.len() {
            return Err(ExtractError::Invalid(
                "invalid BitLocker metadata entry size".to_owned(),
            ));
        }
        let value_type = u16_at(block, position + 4).unwrap_or_default();
        let value = &block[position + 8..position + size];
        position += size;

        if value_type == 0x8 {
            parse_vmk(value, &mut salt, &mut found)?;
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

fn extract(artifact: &Artifact) -> Result<Vec<BitLocker>, ExtractError> {
    let source = artifact.primary();
    let guid_offset = signature(source).ok_or_else(|| {
        ExtractError::Unsupported("not a BitLocker volume".to_owned())
    })?;

    let mut recoveries = Vec::new();
    let mut last_error = None;
    for offset in metadata_offsets(source, guid_offset)? {
        let mut block = [0u8; BLOCK_SIZE];
        match source.read_exact_at(offset, &mut block) {
            Ok(()) => match parse_block(&block) {
                Ok(mut found) => {
                    recoveries.append(&mut found);
                    break;
                }
                Err(error) => last_error = Some(error),
            },
            Err(_) => {
                last_error = Some(ExtractError::Invalid(
                    "truncated BitLocker metadata block".to_owned(),
                ));
            }
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }
    if recoveries.is_empty() {
        return Err(ExtractError::Unsupported(
            "BitLocker volume has no password-protected VMK".to_owned(),
        ));
    }

    Ok(recoveries
        .into_iter()
        .map(|recovery| BitLocker {
            kind: 1,
            salt_size: 16,
            salt: recovery.salt,
            iterations: ITERATIONS,
            nonce_size: 12,
            nonce: recovery.nonce,
            data_size: 60,
            data: recovery.data,
        })
        .collect())
}

/// Extractor for BitLocker volume metadata.
pub struct BitlockerExtractor;

impl Extractor for BitlockerExtractor {
    fn slug(&self) -> &'static str {
        BitLocker::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if signature(artifact.primary()).is_none() {
            return Probe::No;
        }
        match extract(artifact) {
            Ok(_) => Probe::yes("BitLocker FVE volume metadata"),
            Err(ExtractError::Unsupported(_)) => {
                Probe::maybe("BitLocker volume without a password-protected VMK")
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
