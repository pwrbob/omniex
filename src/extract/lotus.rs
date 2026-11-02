//! Lotus Notes/Domino 5 ID-file extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Lotus5;
use crate::{HashType, HashValue};

pub struct Lotus5Extractor;

fn parse(artifact: &Artifact) -> Result<Lotus5, ExtractError> {
    let source = artifact.primary();
    if source.len() < 0xD8 {
        return Err(ExtractError::Unsupported(
            "Lotus ID file is too short".to_owned(),
        ));
    }
    let mut size = [0; 2];
    source
        .read_exact_at(0xD6, &mut size)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Lotus ID: {error}")))?;
    let size = u16::from_le_bytes(size) as usize;
    if !(0x10..=0x64).contains(&size) || 0xD8 + size as u64 > source.len() {
        return Err(ExtractError::Invalid(
            "invalid Lotus ID blob length".to_owned(),
        ));
    }
    let mut blob = vec![0; size];
    source
        .read_exact_at(0xD8, &mut blob)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Lotus ID blob: {error}")))?;
    if size != 16 {
        return Err(ExtractError::Unsupported(
            "Lotus 5 hashes require a 16-byte user blob".to_owned(),
        ));
    }
    Ok(Lotus5 {
        digest: blob.try_into().expect("16-byte blob"),
    })
}

impl Extractor for Lotus5Extractor {
    fn slug(&self) -> &'static str {
        Lotus5::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Lotus Notes 5 user ID blob"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
