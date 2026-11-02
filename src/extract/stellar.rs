//! Stargazer Stellar wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Stellar;
use crate::{HashType, HashValue};

pub struct StellarExtractor;

const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 12;
const CIPHERTEXT_SIZE: usize = 72;
const MAX_DEPTH: usize = 16;

fn record(value: &Value) -> Result<Option<Stellar>, ExtractError> {
    let Value::Array(fields) = value else {
        return Ok(None);
    };
    if fields.len() != 3 || fields[0].as_str() != Some("1") {
        return Ok(None);
    }
    let Value::Array(blob) = &fields[2] else {
        return Ok(None);
    };
    if blob.len() != 2 {
        return Ok(None);
    }
    let Some(salt) = fields[1].as_str() else {
        return Err(ExtractError::Invalid(
            "Stellar wallet salt is not a string".to_owned(),
        ));
    };
    let Some(iv) = blob[0].as_str() else {
        return Err(ExtractError::Invalid(
            "Stellar wallet IV is not a string".to_owned(),
        ));
    };
    let Some(ciphertext) = blob[1].as_str() else {
        return Err(ExtractError::Invalid(
            "Stellar wallet ciphertext is not a string".to_owned(),
        ));
    };
    let salt = STANDARD
        .decode(salt)
        .map_err(|_| ExtractError::Invalid("invalid Stellar wallet salt base64".to_owned()))?;
    let iv = STANDARD
        .decode(iv)
        .map_err(|_| ExtractError::Invalid("invalid Stellar wallet IV base64".to_owned()))?;
    let ciphertext = STANDARD.decode(ciphertext).map_err(|_| {
        ExtractError::Invalid("invalid Stellar wallet ciphertext base64".to_owned())
    })?;
    if salt.len() != SALT_SIZE {
        return Err(ExtractError::Invalid(
            "Stellar wallet salt must be 16 bytes".to_owned(),
        ));
    }
    if iv.len() != IV_SIZE {
        return Err(ExtractError::Invalid(
            "Stellar wallet IV must be 12 bytes".to_owned(),
        ));
    }
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(ExtractError::Invalid(
            "Stellar wallet ciphertext must be 72 bytes".to_owned(),
        ));
    }
    Ok(Some(Stellar {
        salt,
        iv,
        ciphertext,
    }))
}

fn collect(value: &Value, depth: usize, hashes: &mut Vec<Stellar>) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::Invalid(
            "Stellar wallet nesting is too deep".to_owned(),
        ));
    }
    if let Some(hash) = record(value)? {
        hashes.push(hash);
    }
    match value {
        Value::Object(map) => {
            for value in map.values() {
                collect(value, depth + 1, hashes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect(value, depth + 1, hashes)?;
            }
        }
        Value::String(text) if text.starts_with('{') || text.starts_with('[') => {
            let nested: Value = serde_json::from_str(text).map_err(|error| {
                ExtractError::Invalid(format!("invalid nested Stellar JSON: {error}"))
            })?;
            collect(&nested, depth + 1, hashes)?;
        }
        _ => {}
    }
    Ok(())
}

fn parse(artifact: &Artifact) -> Result<Vec<Stellar>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Stellar wallet is not UTF-8".to_owned()))?;
    let document: Value = serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid Stellar wallet JSON: {error}")))?;
    let mut hashes = Vec::new();
    collect(&document, 0, &mut hashes)?;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Stargazer Stellar wallet found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for StellarExtractor {
    fn slug(&self) -> &'static str {
        Stellar::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Stargazer Stellar wallet"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
