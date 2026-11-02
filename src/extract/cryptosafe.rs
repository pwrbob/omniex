//! cryptoSafe vault extraction.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Cryptosafe;
use crate::{HashType, HashValue};

pub struct CryptosafeExtractor;

fn payload(artifact: &Artifact) -> Result<String, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = std::str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("cryptoSafe vault is not ASCII".to_owned()))?;
    let payload: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if payload.is_empty() {
        return Err(ExtractError::Unsupported(
            "empty cryptoSafe vault".to_owned(),
        ));
    }
    let decoded = STANDARD
        .decode(&payload)
        .map_err(|_| ExtractError::Invalid("invalid cryptoSafe base64".to_owned()))?;
    if decoded.len() < 32 || decoded.len() % 16 != 0 {
        return Err(ExtractError::Unsupported(
            "not a cryptoSafe vault".to_owned(),
        ));
    }
    Ok(payload)
}

impl Extractor for CryptosafeExtractor {
    fn slug(&self) -> &'static str {
        Cryptosafe::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match payload(artifact) {
            Ok(_) => Probe::maybe("base64 cryptoSafe vault without a signature"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(Cryptosafe {
            version: 1,
            payload: payload(artifact)?,
        }) as Box<dyn HashValue>])
    }
}
