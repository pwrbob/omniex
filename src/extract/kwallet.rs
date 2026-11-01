//! Legacy KDE KWallet extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Kwallet;
use crate::{HashType, HashValue};

pub struct KwalletExtractor;

const MAGIC: &[u8] = b"KWALLET\n\r\0\r\n";

fn parse(artifact: &Artifact) -> Result<Kwallet, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ExtractError::Unsupported(
            "not a KDE KWallet file".to_owned(),
        ));
    }
    let version = data
        .get(12..16)
        .ok_or_else(|| ExtractError::Invalid("truncated KWallet header".to_owned()))?;
    if version[0] != 0 {
        return Err(ExtractError::Unsupported(
            "unsupported KWallet major version".to_owned(),
        ));
    }
    if version[1] != 0 {
        return Err(ExtractError::Unsupported(
            "salted KWallet files need their .salt sidecar and are not supported".to_owned(),
        ));
    }
    if !matches!(version[2], 0 | 3) || version[3] != 0 {
        return Err(ExtractError::Unsupported(
            "unsupported KWallet cipher or hash".to_owned(),
        ));
    }

    let mut offset = 16;
    let count = data
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| ExtractError::Invalid("truncated KWallet folder count".to_owned()))?
        as usize;
    offset += 4;
    if count > 0xffff {
        return Err(ExtractError::Invalid(
            "KWallet folder count is unreasonable".to_owned(),
        ));
    }
    for _ in 0..count {
        offset = offset
            .checked_add(16)
            .ok_or_else(|| ExtractError::Invalid("truncated KWallet folder".to_owned()))?;
        let size = data
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| ExtractError::Invalid("truncated KWallet entry".to_owned()))?
            as usize;
        offset += 4;
        offset = offset
            .checked_add(size.saturating_mul(16))
            .filter(|offset| *offset <= data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated KWallet entries".to_owned()))?;
    }

    let encrypted = &data[offset..];
    if encrypted.len() < 88 || encrypted.len() % 8 != 0 {
        return Err(ExtractError::Invalid(
            "invalid KWallet encrypted payload length".to_owned(),
        ));
    }
    let size = u32::try_from(encrypted.len())
        .map_err(|_| ExtractError::Invalid("KWallet payload is too large".to_owned()))?;
    let prefix = &encrypted[..65.min(encrypted.len())];
    Ok(Kwallet {
        version: size,
        data: crate::format::hex(prefix),
    })
}

impl Extractor for KwalletExtractor {
    fn slug(&self) -> &'static str {
        Kwallet::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("legacy KWallet file"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
