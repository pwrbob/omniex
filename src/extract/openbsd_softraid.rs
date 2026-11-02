//! OpenBSD softraid crypto metadata extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::OpenbsdSoftraid;
use crate::{HashType, HashValue};

pub struct OpenbsdSoftraidExtractor;

const MAGIC: &[u8] = b"marcCRAM";
const RAID_TYPE: &[u8] = b"SR CRYPTO";
const MAX_HEADER: u64 = 0xaa0 + 81920;

fn parse(artifact: &Artifact) -> Result<OpenbsdSoftraid, ExtractError> {
    let len = artifact.primary().len().min(MAX_HEADER);
    let mut headers = vec![0; len as usize];
    artifact
        .primary()
        .read_exact_at(0, &mut headers)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    let start = headers
        .windows(MAGIC.len())
        .position(|window| window == MAGIC)
        .ok_or_else(|| ExtractError::Unsupported("softraid magic not found".to_owned()))?;
    let headers = &headers[start..];
    if headers.get(72..81) != Some(RAID_TYPE) {
        return Err(ExtractError::Unsupported(
            "not an OpenBSD softraid crypto volume".to_owned(),
        ));
    }
    if headers.get(260) != Some(&1) || headers.get(284) != Some(&2) {
        return Err(ExtractError::Unsupported(
            "unsupported softraid optional header or encryption type".to_owned(),
        ));
    }
    let kdf = headers
        .get(2416..2420)
        .map(LittleEndian::read_u32)
        .ok_or_else(|| ExtractError::Invalid("truncated softraid metadata".to_owned()))?;
    if !matches!(kdf, 1 | 3) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported softraid KDF type {kdf}"
        )));
    }
    let iterations = headers
        .get(2420..2424)
        .map(LittleEndian::read_u32)
        .ok_or_else(|| ExtractError::Invalid("truncated softraid metadata".to_owned()))?;
    let salt = headers
        .get(2424..2552)
        .ok_or_else(|| ExtractError::Invalid("truncated softraid salt".to_owned()))?;
    let keys = headers
        .get(364..2412)
        .ok_or_else(|| ExtractError::Invalid("truncated softraid keys".to_owned()))?;
    let hmac = headers
        .get(2676..2696)
        .ok_or_else(|| ExtractError::Invalid("truncated softraid HMAC".to_owned()))?;

    Ok(OpenbsdSoftraid {
        iterations,
        data: format!(
            "{}${}${}${}",
            crate::format::hex(salt),
            crate::format::hex(keys),
            crate::format::hex(hmac),
            kdf
        ),
    })
}

impl Extractor for OpenbsdSoftraidExtractor {
    fn slug(&self) -> &'static str {
        OpenbsdSoftraid::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("OpenBSD softraid crypto metadata"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
