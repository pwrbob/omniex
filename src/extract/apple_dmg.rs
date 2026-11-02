//! Apple DMG `encrcdsa` AES key-blob extraction (`$dmg$3`).

use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::AppleDmg;
use crate::{HashType, HashValue};

pub struct AppleDmgExtractor;

const HEADER_SIZE: usize = 264;
const MAGIC: &[u8] = b"encrcdsa";
const AES_ALGORITHM: u32 = 0x8000_0001;

fn number<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ExtractError> {
    data.get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ExtractError::Invalid("truncated DMG header".to_owned()))
}

fn parse(artifact: &Artifact) -> Result<AppleDmg, ExtractError> {
    let source = artifact.primary();
    let mut header = vec![0; HEADER_SIZE];
    source.read_exact_at(0, &mut header).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if &header[..8] != MAGIC {
        return Err(ExtractError::Unsupported(
            "not an encrcdsa DMG".to_owned(),
        ));
    }
    let version = BigEndian::read_u32(&number::<4>(&header, 8)?);
    if version != 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported encrcdsa header version {version}"
        )));
    }
    let datasize = BigEndian::read_u64(&number::<8>(&header, 56)?);
    let dataoffset = BigEndian::read_u64(&number::<8>(&header, 64)?);
    let iterations = BigEndian::read_u32(&number::<4>(&header, 104)?);
    let salt_len = BigEndian::read_u32(&number::<4>(&header, 108)?);
    let salt = &header[112..132];
    let key_bits = BigEndian::read_u32(&number::<4>(&header, 180)?);
    let algorithm = BigEndian::read_u32(&number::<4>(&header, 184)?);
    let blob_size = BigEndian::read_u32(&number::<4>(&header, 196)?);
    let key_blob = &header[200..264];

    if salt_len != 20 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported DMG salt length {salt_len}"
        )));
    }
    if key_bits != 192 || algorithm != AES_ALGORITHM || blob_size != 64 {
        return Err(ExtractError::Unsupported(
            "DMG key blob is not an AES-192 blob".to_owned(),
        ));
    }
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "DMG iteration count is zero".to_owned(),
        ));
    }
    if datasize == 0 {
        return Err(ExtractError::Invalid("DMG data size is zero".to_owned()));
    }
    if dataoffset >= source.len() {
        return Err(ExtractError::Invalid(
            "DMG data offset is outside the artifact".to_owned(),
        ));
    }
    Ok(AppleDmg {
        salt_size: u8::try_from(salt_len).unwrap_or(20),
        salt: salt.try_into().expect("twenty-byte DMG salt"),
        key_bits: u16::try_from(key_bits).unwrap_or(192),
        blob_size: u8::try_from(blob_size).unwrap_or(64),
        key_blob: key_blob.try_into().expect("sixty-four-byte DMG key blob"),
        iterations,
    })
}

impl Extractor for AppleDmgExtractor {
    fn slug(&self) -> &'static str {
        AppleDmg::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Apple DMG encrcdsa AES-192 key blob"),
            Err(ExtractError::Unsupported(reason)) if reason.starts_with("unsupported encrcdsa") => {
                Probe::maybe(reason)
            }
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
