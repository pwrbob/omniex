//! Apple DMG encrcdsa v2 extraction.

use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::DmgJohn;
use crate::{HashType, HashValue};

pub struct DmgExtractor;

const HEADER_SIZE: usize = 264;
const MAGIC: &[u8] = b"encrcdsa";

fn number<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ExtractError> {
    data.get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ExtractError::Invalid("truncated DMG header".to_owned()))
}

fn parse(artifact: &Artifact) -> Result<DmgJohn, ExtractError> {
    let source = artifact.primary();
    let mut header = vec![0; HEADER_SIZE];
    source.read_exact_at(0, &mut header).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if &header[..8] != MAGIC {
        return Err(ExtractError::Unsupported(
            "not an encrcdsa v2 DMG".to_owned(),
        ));
    }
    let datasize = BigEndian::read_u64(&number::<8>(&header, 56)?);
    let dataoffset = BigEndian::read_u64(&number::<8>(&header, 64)?);
    let iterations = BigEndian::read_u32(&number::<4>(&header, 104)?);
    let salt_len = BigEndian::read_u32(&number::<4>(&header, 108)?);
    if salt_len > 32 {
        return Err(ExtractError::Unsupported(
            "DMG salt length is too large".to_owned(),
        ));
    }
    let salt = &header[112..112 + salt_len as usize];
    let blob_iv = &header[148..180];
    let keyblob_size = BigEndian::read_u32(&number::<4>(&header, 196)?);
    let keyblob = &header[200..264];
    if keyblob_size > 64 {
        return Err(ExtractError::Unsupported(
            "DMG key blob is too large".to_owned(),
        ));
    }

    let chunks = datasize
        .div_ceil(4096)
        .checked_sub(2)
        .ok_or_else(|| ExtractError::Invalid("DMG data size is too small".to_owned()))?;
    let data_size = datasize
        .checked_sub(chunks * 4096)
        .ok_or_else(|| ExtractError::Invalid("invalid DMG data layout".to_owned()))?;
    let chunk1_offset = dataoffset
        .checked_add(chunks * 4096)
        .ok_or_else(|| ExtractError::Invalid("DMG data offset overflow".to_owned()))?;
    let chunk1_len = usize::try_from(data_size)
        .map_err(|_| ExtractError::Invalid("DMG chunk is too large".to_owned()))?;
    let mut chunk1 = vec![0; chunk1_len];
    source
        .read_exact_at(chunk1_offset, &mut chunk1)
        .map_err(|error| ExtractError::Invalid(format!("cannot read DMG data: {error}")))?;
    let mut chunk2 = [0; 4096];
    source
        .read_exact_at(dataoffset, &mut chunk2)
        .map_err(|error| ExtractError::Invalid(format!("cannot read DMG data: {error}")))?;

    let mut keyblob_hex = crate::format::hex(&keyblob[..keyblob_size as usize]);
    while keyblob_hex.len() < keyblob_size as usize * 2 {
        keyblob_hex.push('0');
    }

    Ok(DmgJohn {
        data: format!(
            "2*{}*{}*32*{}*{}*{}*{}*{}*{}*1*{}*{}",
            salt_len,
            crate::format::hex(salt),
            crate::format::hex(&blob_iv[..32]),
            keyblob_size,
            keyblob_hex,
            chunks,
            data_size,
            crate::format::hex(&chunk1),
            crate::format::hex(chunk2),
            iterations
        ),
    })
}

impl Extractor for DmgExtractor {
    fn slug(&self) -> &'static str {
        DmgJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Apple DMG encrcdsa v2 header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
