//! BitShares backup wallet extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::BitsharesJohn;
use crate::{HashType, HashValue};

pub struct BitsharesExtractor;

impl Extractor for BitsharesExtractor {
    fn slug(&self) -> &'static str {
        BitsharesJohn::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().is_empty() {
            return Probe::No;
        }
        if artifact.label().to_ascii_lowercase().ends_with(".bin") {
            Probe::maybe("BitShares backup wallet file extension")
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
                "BitShares backup wallet is empty".to_owned(),
            ));
        }
        Ok(vec![Box::new(BitsharesJohn {
            data: format!("1*{}", crate::format::hex(&data)),
        }) as Box<dyn HashValue>])
    }
}
