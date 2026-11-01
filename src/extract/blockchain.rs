//! Blockchain.com wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Blockchain;
use crate::{HashType, HashValue};

pub struct BlockchainExtractor;

fn parse(artifact: &Artifact) -> Result<Blockchain, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let document: Value = serde_json::from_slice(&data)
        .map_err(|error| ExtractError::Invalid(format!("invalid Blockchain JSON: {error}")))?;
    if let (Some(version), Some(payload), Some(iterations)) = (
        document.get("version"),
        document.get("payload").and_then(Value::as_str),
        document.get("pbkdf2_iterations").and_then(Value::as_u64),
    ) {
        if !matches!(version.as_str(), Some("2" | "3" | "4"))
            && !matches!(version.as_u64(), Some(2..=4))
        {
            return Err(ExtractError::Unsupported(
                "unsupported Blockchain wallet version".to_owned(),
            ));
        }
        let payload = STANDARD
            .decode(payload)
            .map_err(|_| ExtractError::Invalid("invalid Blockchain payload base64".to_owned()))?;
        return Ok(Blockchain {
            version: "v2".to_owned(),
            iterations: u32::try_from(iterations).map_err(|_| {
                ExtractError::Invalid("Blockchain iterations are too large".to_owned())
            })?,
            length: u32::try_from(payload.len())
                .map_err(|_| ExtractError::Invalid("Blockchain payload is too large".to_owned()))?,
            data: payload,
        });
    }
    if document.get("guid").and_then(Value::as_str).is_some() {
        let length = u32::try_from(data.len())
            .map_err(|_| ExtractError::Invalid("Blockchain wallet is too large".to_owned()))?;
        return Ok(Blockchain {
            version: "1".to_owned(),
            iterations: length,
            length,
            data,
        });
    }
    Err(ExtractError::Unsupported(
        "not a Blockchain.com wallet".to_owned(),
    ))
}

impl Extractor for BlockchainExtractor {
    fn slug(&self) -> &'static str {
        Blockchain::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Blockchain wallet JSON"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
