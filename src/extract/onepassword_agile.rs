//! 1Password agilekeychain key extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{AgilekeychainJohn, OnepasswordAgile};
use crate::{HashType, HashValue};

pub struct AgileKeychainExtractor;
pub struct OnepasswordAgileExtractor;

struct Key {
    iterations: u32,
    salt: Vec<u8>,
    data: Vec<u8>,
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let value =
        value.trim_matches(|character: char| character.is_whitespace() || character == '\0');
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value.trim_end_matches('=')))
        .ok()
}

fn keys(artifact: &Artifact) -> Result<Vec<Key>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data).map_err(|_| {
        ExtractError::Invalid("1Password encryptionKeys.js is not UTF-8".to_owned())
    })?;
    let document: Value = serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid 1Password JSON: {error}")))?;
    let list = document
        .get("list")
        .and_then(Value::as_array)
        .ok_or_else(|| ExtractError::Unsupported("missing 1Password key list".to_owned()))?;
    if list.is_empty() {
        return Err(ExtractError::Unsupported(
            "1Password key list is empty".to_owned(),
        ));
    }

    let mut keys = Vec::with_capacity(list.len());
    for entry in list {
        let data = entry
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| ExtractError::Invalid("missing 1Password key data".to_owned()))?;
        let data = decode_base64(data)
            .ok_or_else(|| ExtractError::Invalid("invalid 1Password key data".to_owned()))?;
        let iterations = entry
            .get("iterations")
            .and_then(Value::as_u64)
            .unwrap_or(1000);
        let iterations = u32::try_from(iterations)
            .map_err(|_| ExtractError::Invalid("1Password iterations are too large".to_owned()))?;
        let (salt, data) = if let Some(data) = data.strip_prefix(b"Salted__") {
            if data.len() < 8 {
                return Err(ExtractError::Invalid(
                    "1Password salted key is truncated".to_owned(),
                ));
            }
            (data[..8].to_vec(), data[8..].to_vec())
        } else {
            (vec![0; 16], data)
        };
        if data.is_empty() {
            return Err(ExtractError::Invalid(
                "1Password key payload is empty".to_owned(),
            ));
        }
        keys.push(Key {
            iterations,
            salt,
            data,
        });
    }
    Ok(keys)
}

impl Extractor for AgileKeychainExtractor {
    fn slug(&self) -> &'static str {
        AgilekeychainJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match keys(artifact) {
            Ok(_) => Probe::yes("1Password agilekeychain key list"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let keys = keys(artifact)?;
        let mut data = keys.len().to_string();
        for key in keys {
            data.push_str(&format!(
                "*{}*{}*{}*{}*{}",
                key.iterations,
                key.salt.len(),
                crate::format::hex(&key.salt),
                key.data.len(),
                crate::format::hex(&key.data)
            ));
        }
        Ok(vec![
            Box::new(AgilekeychainJohn { data }) as Box<dyn HashValue>
        ])
    }
}

impl Extractor for OnepasswordAgileExtractor {
    fn slug(&self) -> &'static str {
        OnepasswordAgile::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match keys(artifact) {
            Ok(_) => Probe::yes("1Password agilekeychain key list"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(keys(artifact)?
            .into_iter()
            .map(|key| {
                Box::new(OnepasswordAgile {
                    iterations: key.iterations,
                    salt: crate::format::hex(&key.salt),
                    data: key.data,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
