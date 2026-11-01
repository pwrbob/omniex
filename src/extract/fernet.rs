//! Fernet token extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Fernet;
use crate::{HashType, HashValue, Parse, ParseOptions};

pub struct FernetExtractor;

fn token(artifact: &Artifact) -> Result<String, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Fernet token file is not UTF-8".to_owned()))?;
    let text = text.trim();
    Fernet::parse(text, &ParseOptions::default())
        .map(|token| token.token)
        .map_err(|error| ExtractError::Invalid(format!("invalid Fernet token: {error}")))
}

impl Extractor for FernetExtractor {
    fn slug(&self) -> &'static str {
        Fernet::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match token(artifact) {
            Ok(_) => Probe::maybe("Fernet token text"),
            Err(ExtractError::Invalid(_)) => Probe::No,
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(Fernet {
            token: token(artifact)?,
        }) as Box<dyn HashValue>])
    }
}
