//! Apple DMG encrcdsa v1 and v2 extraction.

use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe};
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

const V1_HEADER_SIZE: usize = 1276;
const V1_MAGIC: &[u8] = b"cdsaencr";

fn parse_v1(source: &dyn super::ReadAt) -> Result<DmgJohn, ExtractError> {
    if source.len() < V1_HEADER_SIZE as u64 {
        return Err(ExtractError::Invalid(
            "DMG v1 header is truncated".to_owned(),
        ));
    }
    let mut header = vec![0; V1_HEADER_SIZE];
    source
        .read_exact_at(source.len() - V1_HEADER_SIZE as u64, &mut header)
        .map_err(|error| ExtractError::Invalid(format!("cannot read DMG v1 header: {error}")))?;
    let iterations = BigEndian::read_u32(&number::<4>(&header, 48)?);
    let salt_len = BigEndian::read_u32(&number::<4>(&header, 52)?);
    let aes_len = BigEndian::read_u32(&number::<4>(&header, 136)?);
    let hmac_len = BigEndian::read_u32(&number::<4>(&header, 436)?);
    if salt_len > 48 || aes_len > 296 || hmac_len > 300 {
        return Err(ExtractError::Unsupported(
            "DMG v1 key blob is too large".to_owned(),
        ));
    }
    let salt = &header[56..56 + salt_len as usize];
    let aes_key = &header[140..140 + aes_len as usize];
    let hmac_key = &header[440..440 + hmac_len as usize];
    Ok(DmgJohn {
        data: format!(
            "1*{}*{}*{}*{}*{}*{}*{}",
            salt_len,
            crate::format::hex(salt),
            aes_len,
            crate::format::hex(aes_key),
            hmac_len,
            crate::format::hex(hmac_key),
            iterations
        ),
    })
}

fn parse(artifact: &Artifact) -> Result<DmgJohn, ExtractError> {
    let source = artifact.primary();
    if source.len() >= 8 {
        let mut tail = [0; 8];
        source
            .read_exact_at(source.len() - 8, &mut tail)
            .map_err(|error| ExtractError::Invalid(format!("cannot read DMG tail: {error}")))?;
        if tail.as_slice() == V1_MAGIC {
            return parse_v1(source);
        }
    }
    let mut header = vec![0; HEADER_SIZE];
    source.read_exact_at(0, &mut header).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if &header[..8] != MAGIC {
        return Err(ExtractError::Unsupported("not an encrypted DMG".to_owned()));
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

    let sparsebundle = artifact.member("data").is_some();
    let (chunks, data_size, dataoffset) = if sparsebundle {
        (1, 8192, 0)
    } else {
        let chunks = datasize
            .div_ceil(4096)
            .checked_sub(2)
            .ok_or_else(|| ExtractError::Invalid("DMG data size is too small".to_owned()))?;
        let data_size = datasize
            .checked_sub(chunks * 4096)
            .ok_or_else(|| ExtractError::Invalid("invalid DMG data layout".to_owned()))?;
        (chunks, data_size, dataoffset)
    };
    let chunk1_offset = dataoffset
        .checked_add(chunks * 4096)
        .ok_or_else(|| ExtractError::Invalid("DMG data offset overflow".to_owned()))?;
    let chunk1_len = usize::try_from(data_size)
        .map_err(|_| ExtractError::Invalid("DMG chunk is too large".to_owned()))?;
    let data_source = artifact.member("data").unwrap_or(source);
    let mut chunk1 = vec![0; chunk1_len];
    data_source
        .read_exact_at(chunk1_offset, &mut chunk1)
        .map_err(|error| ExtractError::Invalid(format!("cannot read DMG data: {error}")))?;
    let mut chunk2 = [0; 4096];
    data_source
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

const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::optional("data", "sparsebundle data fork")];

impl Extractor for DmgExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        DmgJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Apple DMG encrcdsa header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
