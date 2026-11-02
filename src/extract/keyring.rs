//! GNOME Keyring file extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Keyring;
use crate::{HashType, HashValue};

pub struct KeyringExtractor;

const MAGIC: &[u8] = b"GnomeKeyring\n\r\0\n";

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn parse_at(data: &[u8], start: usize) -> Result<Keyring, ExtractError> {
    let mut offset = start + MAGIC.len();
    let version = data
        .get(offset..offset + 2)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring version".to_owned()))?;
    if version != [0, 1] && version != [0, 0] {
        return Err(ExtractError::Unsupported(
            "unsupported GNOME Keyring version".to_owned(),
        ));
    }
    offset += 2;
    let crypto = *data
        .get(offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring crypto".to_owned()))?;
    let hash = *data
        .get(offset + 1)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring hash".to_owned()))?;
    if crypto != 0 || hash != 0 {
        return Err(ExtractError::Unsupported(
            "unsupported GNOME Keyring cipher or hash".to_owned(),
        ));
    }
    offset += 2;
    let name_length = be_u32(data, offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring name length".to_owned()))?
        as usize;
    offset += 4;
    offset = offset
        .checked_add(name_length)
        .filter(|offset| *offset <= data.len())
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring name".to_owned()))?;
    offset = offset
        .checked_add(8 + 8 + 4 + 4)
        .filter(|offset| *offset <= data.len())
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring timestamps".to_owned()))?;
    let iterations = be_u32(data, offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring iterations".to_owned()))?;
    offset += 4;
    let salt = data
        .get(offset..offset + 8)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring salt".to_owned()))?;
    offset += 8;
    offset = offset
        .checked_add(16 + 8)
        .filter(|offset| *offset <= data.len())
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring header".to_owned()))?;
    let digest = data
        .get(offset..offset + 16)
        .ok_or_else(|| ExtractError::Invalid("truncated Keyring digest".to_owned()))?;
    Ok(Keyring {
        fields: format!(
            "{}*{}*{}*0*{}",
            crate::format::hex(salt),
            iterations,
            digest.len(),
            crate::format::hex(digest)
        ),
    })
}

fn parse(artifact: &Artifact) -> Result<Vec<Keyring>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut hashes = Vec::new();
    let mut offset = 0;
    while let Some(position) = data[offset..]
        .windows(MAGIC.len())
        .position(|window| window == MAGIC)
    {
        let start = offset + position;
        if let Ok(hash) = parse_at(&data, start) {
            hashes.push(hash);
        }
        offset = start + MAGIC.len();
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "not a GNOME Keyring file".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for KeyringExtractor {
    fn slug(&self) -> &'static str {
        Keyring::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("GNOME Keyring header"),
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
