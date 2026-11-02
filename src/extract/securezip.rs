//! SecureZIP AES archive extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Securezip;
use crate::{HashType, HashValue};

pub struct SecurezipExtractor;

const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const AES_METHOD: u16 = 99;

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2).map(LittleEndian::read_u16)
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4).map(LittleEndian::read_u32)
}

fn parse_entry(data: &[u8], start: usize) -> Option<Securezip> {
    let header = data.get(start..start + 30)?;
    let version = LittleEndian::read_u16(&header[4..6]) & 0xff;
    let flags = LittleEndian::read_u16(&header[6..8]);
    let method = LittleEndian::read_u16(&header[8..10]);
    let crc = LittleEndian::read_u32(&header[14..18]);
    let decomp_len = LittleEndian::read_u32(&header[22..26]);
    let name_len = LittleEndian::read_u16(&header[26..28]) as usize;
    let extra_len = LittleEndian::read_u16(&header[28..30]) as usize;

    if flags & FLAG_ENCRYPTED == 0 || method == AES_METHOD {
        return None;
    }
    if flags & FLAG_STRONG_ENCRYPTION == 0 && version != 51 && version != 52 && version < 61 {
        return None;
    }

    let name = data.get(start + 30..start + 30 + name_len)?;
    let _ = extra_len;
    let offset = start.checked_add(30 + name_len)?;
    let mut position = offset;

    let iv_size = read_u16(data, position)? as usize;
    position += 2;
    if iv_size > 16 {
        return None;
    }
    let mut iv = data.get(position..position + iv_size)?.to_vec();
    position += iv_size;
    let _size = read_u32(data, position)?;
    position += 4;
    let format = read_u16(data, position)?;
    position += 2;
    if format != 3 {
        return None;
    }
    let algorithm = read_u16(data, position)?;
    position += 2;
    let kind = match algorithm {
        0x660e..=0x6610 => 1,
        _ => return None,
    };
    let key_bits = read_u16(data, position)?;
    position += 2;
    if !matches!(key_bits, 128 | 192 | 256) {
        return None;
    }
    let _flags = read_u16(data, position)?;
    position += 2;
    let random_size = read_u16(data, position)? as usize;
    position += 2;
    if random_size > 256 {
        return None;
    }
    let random = data.get(position..position + random_size)?;
    position += random_size;
    if read_u32(data, position)? != 0 {
        return None;
    }
    position += 4;
    let verification_size = read_u16(data, position)? as usize;
    position += 2;
    data.get(position..position + verification_size)?;

    if iv_size == 0 {
        iv = Vec::with_capacity(12);
        iv.extend_from_slice(&crc.to_le_bytes());
        iv.extend_from_slice(&(decomp_len as u64).to_le_bytes());
    }

    Some(Securezip {
        version: 0,
        kind,
        key_bits,
        unused: "0".to_owned(),
        iv: crate::format::hex(iv),
        data: crate::format::hex(random),
        rest: format!("0*0*0*{}", String::from_utf8_lossy(name)),
    })
}

fn entries(data: &[u8]) -> Vec<Securezip> {
    let mut hashes = Vec::new();
    let mut offset = 0;
    while let Some(position) = data[offset..]
        .windows(LOCAL_HEADER.len())
        .position(|window| window == LOCAL_HEADER)
    {
        let start = offset + position;
        if let Some(hash) = parse_entry(data, start) {
            hashes.push(hash);
        }
        offset = start + LOCAL_HEADER.len();
    }
    hashes
}

impl Extractor for SecurezipExtractor {
    fn slug(&self) -> &'static str {
        Securezip::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if entries(&data).is_empty() {
            Probe::No
        } else {
            Probe::yes("SecureZIP strong-encryption header")
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = entries(&data);
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no SecureZIP strong-encryption entries found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
