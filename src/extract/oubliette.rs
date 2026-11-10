//! Oubliette database password hash extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{OublietteBlowfish, OublietteIdea};
use crate::{HashType, HashValue};

const MAGIC: &[u8; 5] = b"OUBPF";

fn digest(artifact: &Artifact, algorithm: u8) -> Result<[u8; 32], ExtractError> {
    let mut header = [0u8; 44];
    artifact
        .primary()
        .read_exact_at(0, &mut header)
        .map_err(|_| ExtractError::Unsupported("truncated Oubliette database".to_owned()))?;
    if &header[..5] != MAGIC {
        return Err(ExtractError::Unsupported(
            "not an Oubliette database".to_owned(),
        ));
    }
    if !(1..=3).contains(&header[5]) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Oubliette database version {}",
            header[5]
        )));
    }
    if header[7] != algorithm {
        return Err(ExtractError::Unsupported(
            "unexpected Oubliette algorithm".to_owned(),
        ));
    }
    header[12..44]
        .try_into()
        .map_err(|_| ExtractError::Invalid("truncated Oubliette digest".to_owned()))
}

pub struct OublietteBlowfishExtractor;
pub struct OublietteIdeaExtractor;

impl Extractor for OublietteBlowfishExtractor {
    fn slug(&self) -> &'static str {
        OublietteBlowfish::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match digest(artifact, 0) {
            Ok(_) => Probe::yes("Oubliette Blowfish database"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(OublietteBlowfish {
            digest: digest(artifact, 0)?,
        }) as Box<dyn HashValue>])
    }
}

impl Extractor for OublietteIdeaExtractor {
    fn slug(&self) -> &'static str {
        OublietteIdea::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match digest(artifact, 1) {
            Ok(_) => Probe::yes("Oubliette IDEA database"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(OublietteIdea {
            digest: digest(artifact, 1)?,
        }) as Box<dyn HashValue>])
    }
}
