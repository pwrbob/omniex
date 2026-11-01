//! Monero wallet key-file extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Monero;
use crate::{HashType, HashValue};

pub struct MoneroExtractor;

impl Extractor for MoneroExtractor {
    fn slug(&self) -> &'static str {
        Monero::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().is_empty() {
            return Probe::No;
        }
        if artifact.label().to_ascii_lowercase().ends_with(".keys") {
            Probe::maybe("Monero .keys file extension")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        if data.is_empty() {
            return Err(ExtractError::Invalid(
                "Monero wallet key file is empty".to_owned(),
            ));
        }
        Ok(vec![Box::new(Monero {
            fields: format!("0*{}", crate::format::hex(&data)),
        }) as Box<dyn HashValue>])
    }
}
