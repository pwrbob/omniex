//! FreeBSD GELI metadata extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Geli;
use crate::{HashType, HashValue};

pub struct GeliExtractor;

const MAGIC: &[u8] = b"GEOM::ELI";
const METADATA_SIZE: usize = 511;

fn number<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ExtractError> {
    data.get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ExtractError::Invalid("truncated GELI metadata".to_owned()))
}

fn parse(artifact: &Artifact) -> Result<Geli, ExtractError> {
    let len = artifact.primary().len();
    let start = len.saturating_sub(1024);
    let mut tail = vec![0; (len - start) as usize];
    artifact
        .primary()
        .read_exact_at(start, &mut tail)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    let offset = tail
        .windows(MAGIC.len())
        .position(|window| window == MAGIC)
        .ok_or_else(|| ExtractError::Unsupported("GELI magic not found".to_owned()))?;
    let data = &tail[offset..];
    if data.len() < METADATA_SIZE {
        return Err(ExtractError::Invalid("truncated GELI metadata".to_owned()));
    }

    let version = u32::from_le_bytes(number::<4>(data, 16)?);
    if !(1..=7).contains(&version) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported GELI metadata version {version}"
        )));
    }
    let ealgo = u16::from_le_bytes(number::<2>(data, 24)?);
    if !matches!(ealgo, 11 | 22) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported GELI encryption algorithm {ealgo}"
        )));
    }
    let keylen = u16::from_le_bytes(number::<2>(data, 26)?);
    let aalgo = u16::from_le_bytes(number::<2>(data, 28)?);
    let keys = data[42];
    let iterations = i32::from_le_bytes(number::<4>(data, 43)?);
    let salt = &data[47..111];
    let mkeys = &data[111..495];

    Ok(Geli {
        data: format!(
            "0${}${}${}${}${}${}${}${}",
            version,
            ealgo,
            keylen,
            aalgo,
            keys,
            iterations,
            crate::format::hex(salt),
            crate::format::hex(mkeys)
        ),
    })
}

impl Extractor for GeliExtractor {
    fn slug(&self) -> &'static str {
        Geli::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("GELI metadata"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
