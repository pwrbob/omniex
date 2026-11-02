//! Exodus desktop wallet (`seed.seco`) extraction.

use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Exodus;
use crate::{HashType, HashValue};

pub struct ExodusExtractor;

const HEADER_SIZE: usize = 224;
const METADATA_SIZE: usize = 256;
const MAGIC: &[u8] = b"SECO";
const VERSION_TAG: &[u8] = b"seco-v0-scrypt-aes";

fn parse(artifact: &Artifact) -> Result<Exodus, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let header = data
        .get(..HEADER_SIZE)
        .ok_or_else(|| ExtractError::Invalid("truncated Exodus header".to_owned()))?;
    if &header[..4] != MAGIC || BigEndian::read_u32(&header[4..8]) != 0 {
        return Err(ExtractError::Unsupported("not an Exodus wallet".to_owned()));
    }
    if !header
        .windows(VERSION_TAG.len())
        .any(|window| window == VERSION_TAG)
    {
        return Err(ExtractError::Unsupported(
            "unsupported Exodus wallet version".to_owned(),
        ));
    }
    let metadata_start = HEADER_SIZE + 32;
    let metadata = data
        .get(metadata_start..metadata_start + METADATA_SIZE)
        .ok_or_else(|| ExtractError::Invalid("truncated Exodus metadata".to_owned()))?;
    let salt = metadata[..32].to_vec();
    let n = BigEndian::read_u32(&metadata[32..36]);
    let r = BigEndian::read_u32(&metadata[36..40]);
    let p = BigEndian::read_u32(&metadata[40..44]);
    let iv = metadata[76..88].to_vec();
    let ciphertext = metadata[104..136].to_vec();
    let mac = metadata[88..104].to_vec();
    Ok(Exodus {
        n,
        r,
        p,
        salt,
        iv,
        ciphertext,
        mac,
    })
}

impl Extractor for ExodusExtractor {
    fn slug(&self) -> &'static str {
        Exodus::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Exodus SECO wallet"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
