//! Lotus Notes/Domino 8.5 ID-file extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Lotus85;
use crate::{HashType, HashValue};

pub struct Lotus85Extractor;

fn parse(artifact: &Artifact) -> Result<Lotus85, ExtractError> {
    let source = artifact.primary();
    if source.len() < 0xD8 {
        return Err(ExtractError::Unsupported(
            "Lotus ID file is too short".to_owned(),
        ));
    }
    let mut header = [0; 8];
    source
        .read_exact_at(0, &mut header)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Lotus ID: {error}")))?;
    if header != [0x01, 0x00, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00] {
        return Err(ExtractError::Unsupported("not a Lotus ID file".to_owned()));
    }
    let mut size = [0; 2];
    source
        .read_exact_at(0xD6, &mut size)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Lotus ID: {error}")))?;
    let size = LittleEndian::read_u16(&size) as usize;
    if !(0x10..=0x64).contains(&size) || 0xD8 + size as u64 > source.len() {
        return Err(ExtractError::Invalid(
            "invalid Lotus ID blob length".to_owned(),
        ));
    }
    let mut blob = vec![0; size];
    source
        .read_exact_at(0xD8, &mut blob)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Lotus ID blob: {error}")))?;
    Ok(Lotus85 { data: blob })
}

impl Extractor for Lotus85Extractor {
    fn slug(&self) -> &'static str {
        Lotus85::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Lotus Notes 8.5 user ID blob"),
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
