//! macOS login keychain extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::AppleKeychain;
use crate::{HashType, HashValue};

pub struct AppleKeychainExtractor;

const MAGIC: [u8; 4] = [0xfa, 0xde, 0x07, 0x11];
const HEADER_LENGTH: usize = 92;
const SALT_LENGTH: usize = 20;
const IV_LENGTH: usize = 8;
const CIPHERTEXT_LENGTH: usize = 48;

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn data_at(data: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    data.get(offset..offset + length)
}

fn parse_blob(data: &[u8], start: usize) -> Result<AppleKeychain, ExtractError> {
    let version = be_u32(data, start + 4)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain blob header".to_owned()))?;
    if !matches!(version, 1..=3 | 256) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported keychain blob version {version}"
        )));
    }
    let crypto_offset = be_u32(data, start + 8)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain blob header".to_owned()))?
        as usize;
    let total_length = be_u32(data, start + 12)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain blob header".to_owned()))?
        as usize;
    if total_length < HEADER_LENGTH {
        return Err(ExtractError::Invalid(
            "keychain blob length is too small".to_owned(),
        ));
    }
    if total_length > data.len() - start {
        return Err(ExtractError::Invalid(
            "keychain blob extends past the input".to_owned(),
        ));
    }
    if crypto_offset < HEADER_LENGTH {
        return Err(ExtractError::Invalid(
            "keychain ciphertext offset overlaps the blob header".to_owned(),
        ));
    }
    let salt = data_at(data, start + 44, SALT_LENGTH)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain salt".to_owned()))?;
    let iv = data_at(data, start + 64, IV_LENGTH)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain IV".to_owned()))?;
    let ciphertext = data_at(data, start + crypto_offset, CIPHERTEXT_LENGTH)
        .ok_or_else(|| ExtractError::Invalid("truncated keychain ciphertext".to_owned()))?;
    Ok(AppleKeychain {
        salt: salt.to_vec(),
        iv: iv.to_vec(),
        data: ciphertext.to_vec(),
    })
}

fn parse(artifact: &Artifact) -> Result<AppleKeychain, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.is_empty() {
        return Err(ExtractError::Invalid("keychain file is empty".to_owned()));
    }
    let mut error = ExtractError::Unsupported("no keychain database blob".to_owned());
    let mut found = None;
    for (start, window) in data.windows(MAGIC.len()).enumerate() {
        if window != MAGIC {
            continue;
        }
        match parse_blob(&data, start) {
            Ok(value) => found = Some(value),
            Err(problem) => error = problem,
        }
    }
    found.ok_or(error)
}

impl Extractor for AppleKeychainExtractor {
    fn slug(&self) -> &'static str {
        AppleKeychain::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Apple login keychain database blob"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
