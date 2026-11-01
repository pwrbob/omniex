//! Enpass database extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Enpass;
use crate::{HashType, HashValue};

pub struct EnpassExtractor;

impl Extractor for EnpassExtractor {
    fn slug(&self) -> &'static str {
        Enpass::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().is_empty() {
            return Probe::No;
        }
        if artifact.label().to_ascii_lowercase().ends_with(".enpassdb") {
            Probe::maybe("Enpass database file extension")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let len = artifact.primary().len().min(1024);
        let mut data = vec![0; len as usize];
        artifact
            .primary()
            .read_exact_at(0, &mut data)
            .map_err(|error| {
                ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
            })?;
        if data.is_empty() {
            return Err(ExtractError::Invalid("Enpass database is empty".to_owned()));
        }
        Ok(vec![Box::new(Enpass {
            fields: format!("1$100000${}", crate::format::hex(&data)),
        }) as Box<dyn HashValue>])
    }
}
