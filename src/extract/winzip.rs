//! WinZip AES ZIP entry extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::WinZip;
use crate::{HashType, HashValue};

pub struct WinZipExtractor;

const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const AES_EXTRA: u16 = 0x9901;

fn entries(data: &[u8]) -> Result<Vec<WinZip>, ExtractError> {
    let mut hashes = Vec::new();
    let mut offset = 0;
    while let Some(start) = data[offset..]
        .windows(LOCAL_HEADER.len())
        .position(|window| window == LOCAL_HEADER)
        .map(|position| offset + position)
    {
        offset = start + LOCAL_HEADER.len();
        let header = data
            .get(start..start + 30)
            .ok_or_else(|| ExtractError::Invalid("truncated WinZip local header".to_owned()))?;
        let flags = LittleEndian::read_u16(&header[6..8]);
        let method = LittleEndian::read_u16(&header[8..10]);
        let compressed_size = LittleEndian::read_u32(&header[18..22]) as usize;
        let name_len = LittleEndian::read_u16(&header[26..28]) as usize;
        let extra_len = LittleEndian::read_u16(&header[28..30]) as usize;
        let extra_start = start + 30 + name_len;
        let data_start = extra_start + extra_len;
        let Some(extra) = data.get(extra_start..data_start) else {
            continue;
        };
        let Some(aes) = aes_extra(extra) else {
            continue;
        };
        if flags & 1 == 0 {
            continue;
        }
        let strength = aes.0;
        if aes.1 != *b"AE" || !matches!(strength, 1..=3) || method != 99 {
            continue;
        }
        let salt_len = match strength {
            1 => 8,
            2 => 12,
            3 => 16,
            _ => unreachable!(),
        };
        let Some(entry) = data.get(data_start..data_start + compressed_size) else {
            return Err(ExtractError::Invalid(
                "truncated WinZip AES entry".to_owned(),
            ));
        };
        if entry.len() < salt_len + 12 {
            return Err(ExtractError::Invalid(
                "WinZip AES entry is too short".to_owned(),
            ));
        }
        let data_len = entry.len() - salt_len - 12;
        let salt = &entry[..salt_len];
        let verify = &entry[salt_len..salt_len + 2];
        let ciphertext = &entry[salt_len + 2..salt_len + 2 + data_len];
        let checksum = &entry[entry.len() - 10..];
        hashes.push(WinZip {
            kind: 0,
            mode: strength,
            magic: 0,
            salt: crate::format::hex(salt),
            verify_bytes: crate::format::hex(verify),
            compressed_length: format!("{data_len:x}"),
            data: crate::format::hex(ciphertext),
            checksum: crate::format::hex(checksum),
        });
    }
    Ok(hashes)
}

fn aes_extra(extra: &[u8]) -> Option<(u8, [u8; 2])> {
    let mut offset = 0;
    while offset + 4 <= extra.len() {
        let id = LittleEndian::read_u16(&extra[offset..offset + 2]);
        let size = LittleEndian::read_u16(&extra[offset + 2..offset + 4]) as usize;
        let value = extra.get(offset + 4..offset + 4 + size)?;
        if id == AES_EXTRA && value.len() >= 7 {
            let vendor = [value[2], value[3]];
            return Some((value[4], vendor));
        }
        offset += 4 + size;
    }
    None
}

impl Extractor for WinZipExtractor {
    fn slug(&self) -> &'static str {
        WinZip::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match entries(&data) {
            Ok(hashes) if !hashes.is_empty() => Probe::yes("WinZip AES entry"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = entries(&data)?;
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no WinZip AES entries found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
