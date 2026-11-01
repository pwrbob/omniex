//! PGP self-decrypting archive extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pgpsda;
use crate::{HashType, HashValue};

pub struct PgpsdaExtractor;

const MAGIC: &[u8] = b"PGPSDA";
const HEADER_SIZE: usize = 44;

fn headers(data: &[u8]) -> Vec<&[u8]> {
    data.windows(MAGIC.len())
        .enumerate()
        .filter_map(|(offset, window)| {
            if window != MAGIC {
                return None;
            }
            let header = data.get(offset..offset + HEADER_SIZE)?;
            let file_offset = u32::from_le_bytes(header[6..10].try_into().ok()?);
            ((file_offset as usize) < data.len()).then_some(header)
        })
        .collect()
}

fn parse(artifact: &Artifact) -> Result<Extracted, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let headers = headers(&data);
    if headers.is_empty() {
        return Err(ExtractError::Unsupported(
            "no PGP SDA header found".to_owned(),
        ));
    }
    Ok(headers
        .into_iter()
        .map(|header| {
            let iterations = u16::from_le_bytes(header[34..36].try_into().expect("2 bytes"));
            let salt = header[26..34].try_into().expect("8-byte salt");
            let digest = header[36..44].try_into().expect("8-byte digest");
            Box::new(Pgpsda {
                version: 0,
                iterations: u32::from(iterations),
                salt,
                digest,
            }) as Box<dyn HashValue>
        })
        .collect())
}

impl Extractor for PgpsdaExtractor {
    fn slug(&self) -> &'static str {
        Pgpsda::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("PGP SDA header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        parse(artifact)
    }
}
