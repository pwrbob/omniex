//! STRIP database extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Strip;
use crate::{HashType, HashValue};

const STRIP_BYTES: usize = 1024;
const DATABASE_PAGE_ALIGNMENT: u64 = 512;

fn parse(artifact: &Artifact) -> Result<Strip, ExtractError> {
    if artifact.primary().len() < STRIP_BYTES as u64 {
        return Err(ExtractError::Unsupported(
            "STRIP database is shorter than the first page".to_owned(),
        ));
    }
    let mut page = [0; STRIP_BYTES];
    artifact
        .primary()
        .read_exact_at(0, &mut page)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    Ok(Strip {
        digest: crate::format::hex(page),
    })
}

pub struct StripExtractor;

impl Extractor for StripExtractor {
    fn slug(&self) -> &'static str {
        Strip::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let length = artifact.primary().len();
        if length < STRIP_BYTES as u64 || length % DATABASE_PAGE_ALIGNMENT != 0 {
            return Probe::No;
        }
        Probe::maybe("STRIP encrypted database; no reliable signature")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
