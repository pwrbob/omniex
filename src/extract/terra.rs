//! Terra Station encrypted wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Terra;
use crate::{HashType, HashValue};

pub struct TerraExtractor;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(text: &str, name: &str) -> Result<[u8; N], ExtractError> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(ExtractError::Invalid(format!(
            "Terra {name} must be {} hex characters",
            N * 2
        )));
    }
    let mut out = [0; N];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let high = hex_value(pair[0])
            .ok_or_else(|| ExtractError::Invalid(format!("invalid Terra {name} hex")))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| ExtractError::Invalid(format!("invalid Terra {name} hex")))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn transit_message(value: &Value) -> Option<&str> {
    value
        .get("encrypted_key")
        .or_else(|| value.get("encryptedKey"))
        .or_else(|| value.get("key"))
        .and_then(Value::as_str)
}

fn parse_message(text: &str) -> Result<Terra, ExtractError> {
    let trimmed = text.trim();
    if trimmed.len() < 64 {
        return Err(ExtractError::Invalid(
            "Terra encrypted key is too short".to_owned(),
        ));
    }
    let salt = decode_hex::<16>(&trimmed[..32], "salt")?;
    let iv = decode_hex::<16>(&trimmed[32..64], "iv")?;
    let ciphertext = &trimmed[64..];
    let decoded = STANDARD
        .decode(ciphertext)
        .map_err(|_| ExtractError::Invalid("invalid Terra ciphertext base64".to_owned()))?;
    if decoded.len() != 80 {
        return Err(ExtractError::Invalid(
            "Terra ciphertext must decode to 80 bytes".to_owned(),
        ));
    }
    Ok(Terra {
        salt,
        iv,
        ciphertext: ciphertext.to_owned(),
    })
}

fn parse(artifact: &Artifact) -> Result<Vec<Terra>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.is_empty() {
        return Err(ExtractError::Invalid(
            "Terra wallet file is empty".to_owned(),
        ));
    }
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Terra wallet is not UTF-8".to_owned()))?;

    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if let Some(message) = transit_message(&value) {
            return Ok(vec![parse_message(message)?]);
        }
        if let Some(Value::String(message)) = value.get("encrypted") {
            return Ok(vec![parse_message(message)?]);
        }
        return Err(ExtractError::Unsupported(
            "Terra wallet has no encrypted key".to_owned(),
        ));
    }

    Ok(vec![parse_message(text)?])
}

impl Extractor for TerraExtractor {
    fn slug(&self) -> &'static str {
        Terra::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("Terra Station encrypted key"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
