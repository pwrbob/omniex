//! JSON Web Token extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Jwt;
use crate::{HashType, HashValue, Parse, ParseOptions};

pub struct JwtExtractor;

fn token(artifact: &Artifact) -> Result<Jwt, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("JWT file is not UTF-8".to_owned()))?;
    Jwt::parse(text.trim(), &ParseOptions::default())
        .map_err(|error| ExtractError::Invalid(format!("invalid JWT: {error}")))
}

impl Extractor for JwtExtractor {
    fn slug(&self) -> &'static str {
        Jwt::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match token(artifact) {
            Ok(_) => Probe::maybe("JSON Web Token text"),
            Err(ExtractError::Invalid(_)) => Probe::No,
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(token(artifact)?) as Box<dyn HashValue>])
    }
}
