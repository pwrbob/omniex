//! FreeBSD GELI metadata extraction.

use byteorder::{ByteOrder, LittleEndian};

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

    let version = LittleEndian::read_u32(&number::<4>(data, 16)?);
    if !(0..=7).contains(&version) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported GELI metadata version {version}"
        )));
    }
    let ealgo = LittleEndian::read_u16(&number::<2>(data, 24)?);
    if !matches!(ealgo, 11 | 22) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported GELI encryption algorithm {ealgo}"
        )));
    }
    let keylen = LittleEndian::read_u16(&number::<2>(data, 26)?);
    let (aalgo, keys, iterations_offset, salt_offset, mkeys_offset) = if version == 0 {
        (0, data[40], 41, 45, 109)
    } else {
        (
            LittleEndian::read_u16(&number::<2>(data, 28)?),
            data[42],
            43,
            47,
            111,
        )
    };
    let iterations = LittleEndian::read_i32(&number::<4>(data, iterations_offset)?);
    let salt = &data[salt_offset..salt_offset + 64];
    let mkeys = &data[mkeys_offset..mkeys_offset + 384];

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
