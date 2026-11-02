//! Samsung Android FDE DEK footer extraction.

use std::io;

use byteorder::{ByteOrder, LittleEndian};

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::types::AndroidFdeSamsung;
use omniex::{HashType, HashValue};

pub struct AndroidFdeSamsungExtractor;

const CHUNK_SIZE: usize = 1 << 20;
const MAGIC: &[u8] = &[0xc4, 0xb1, 0xb5, 0xd0];
const DEK_OFFSET: usize = 0x84;
const DEK_LENGTH: usize = 80;
const HEADER_LENGTH: usize = DEK_OFFSET + DEK_LENGTH;

fn candidates(source: &dyn ReadAt) -> io::Result<Vec<u64>> {
    let mut offsets = Vec::new();
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut base = 0u64;
    while base < source.len() {
        let read = source.read_at(base, &mut chunk)?;
        if read < MAGIC.len() {
            break;
        }
        for index in 0..=read - MAGIC.len() {
            if &chunk[index..index + MAGIC.len()] != MAGIC {
                continue;
            }
            let offset = base + index as u64;
            if offset % 512 != 0 {
                continue;
            }
            offsets.push(offset);
        }
        base += read as u64;
    }
    Ok(offsets)
}

fn footer(source: &dyn ReadAt, offset: u64) -> Result<AndroidFdeSamsung, ExtractError> {
    let mut data = vec![0u8; HEADER_LENGTH];
    source.read_exact_at(offset, &mut data).map_err(|error| {
        ExtractError::Invalid(format!("cannot read Android FDE footer: {error}"))
    })?;
    if &data[..4] != MAGIC {
        return Err(ExtractError::Unsupported(
            "not a Samsung Android FDE footer".to_owned(),
        ));
    }
    if LittleEndian::read_u16(&data[4..6]) != 1 {
        return Err(ExtractError::Unsupported(
            "unsupported Samsung Android FDE version".to_owned(),
        ));
    }
    let footer_size = LittleEndian::read_u32(&data[8..12]);
    if footer_size < 0xd8 || footer_size as usize > 0x4000 {
        return Err(ExtractError::Invalid(
            "invalid Samsung Android FDE footer size".to_owned(),
        ));
    }
    if LittleEndian::read_u32(&data[16..20]) != 32 {
        return Err(ExtractError::Unsupported(
            "unsupported Samsung Android DEK length".to_owned(),
        ));
    }
    if &data[0x24..0x27] != b"aes" {
        return Err(ExtractError::Unsupported(
            "unsupported Samsung Android FDE cipher".to_owned(),
        ));
    }
    let dek = &data[DEK_OFFSET..DEK_OFFSET + DEK_LENGTH];
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&dek[32..64]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dek[64..80]);
    Ok(AndroidFdeSamsung {
        salt: dek[..32].to_vec(),
        digest,
        iv,
    })
}

fn extract_all(artifact: &Artifact) -> Result<Vec<AndroidFdeSamsung>, ExtractError> {
    let source = artifact.primary();
    let offsets = candidates(source).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut hashes = Vec::new();
    for offset in offsets {
        match footer(source, offset) {
            Ok(hash) => hashes.push(hash),
            Err(ExtractError::Unsupported(_)) => {}
            Err(error) => return Err(error),
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Samsung Android FDE footer found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for AndroidFdeSamsungExtractor {
    fn slug(&self) -> &'static str {
        AndroidFdeSamsung::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match extract_all(artifact) {
            Ok(_) => Probe::yes("Samsung Android FDE footer"),
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
