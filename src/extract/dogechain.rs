//! Dogechain.info wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Dogechain;
use crate::{HashType, HashValue};

pub struct DogechainExtractor;

const PAYLOAD_SIZE: usize = 240;
const SALT_SIZE: usize = 16;
const MAX_DEPTH: usize = 16;

fn decode(map: &Map<String, Value>, field: &str) -> Result<Vec<u8>, ExtractError> {
    let text = map
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid(format!("missing Dogechain `{field}`")))?;
    STANDARD
        .decode(text)
        .map_err(|_| ExtractError::Invalid(format!("invalid Dogechain `{field}` base64")))
}

fn object(map: &Map<String, Value>) -> Result<Option<Dogechain>, ExtractError> {
    if !map.contains_key("payload") || !map.contains_key("salt") {
        return Ok(None);
    }
    if let Some(cipher) = map.get("cipher").and_then(Value::as_str) {
        if cipher != "AES-CBC" {
            return Err(ExtractError::Unsupported(format!(
                "unsupported Dogechain cipher `{cipher}`"
            )));
        }
    }
    let iterations = map
        .get("pbkdf2_iterations")
        .and_then(Value::as_u64)
        .ok_or_else(|| ExtractError::Invalid("missing Dogechain iterations".to_owned()))?;
    let iterations = u32::try_from(iterations)
        .map_err(|_| ExtractError::Invalid("Dogechain iterations are too large".to_owned()))?;
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "Dogechain iterations must be positive".to_owned(),
        ));
    }
    let data = decode(map, "payload")?;
    if data.len() != PAYLOAD_SIZE {
        return Err(ExtractError::Unsupported(
            "unsupported Dogechain payload size".to_owned(),
        ));
    }
    let salt = decode(map, "salt")?;
    if salt.len() != SALT_SIZE {
        return Err(ExtractError::Invalid(
            "Dogechain salt must be 16 bytes".to_owned(),
        ));
    }
    Ok(Some(Dogechain {
        kind: 0,
        iterations,
        data,
        salt,
    }))
}

fn collect(value: &Value, depth: usize, hashes: &mut Vec<Dogechain>) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::Invalid(
            "Dogechain wallet nesting is too deep".to_owned(),
        ));
    }
    match value {
        Value::Object(map) => {
            if let Some(hash) = object(map)? {
                hashes.push(hash);
            }
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
                ExtractError::Invalid(format!("invalid nested Dogechain JSON: {error}"))
            })?;
            collect(&nested, depth + 1, hashes)?;
        }
        _ => {}
    }
    Ok(())
}

fn parse(artifact: &Artifact) -> Result<Vec<Dogechain>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let document: Value = serde_json::from_slice(&data)
        .map_err(|error| ExtractError::Invalid(format!("invalid Dogechain JSON: {error}")))?;
    let mut hashes = Vec::new();
    collect(&document, 0, &mut hashes)?;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "not a Dogechain wallet".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for DogechainExtractor {
    fn slug(&self) -> &'static str {
        Dogechain::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Dogechain wallet JSON"),
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
