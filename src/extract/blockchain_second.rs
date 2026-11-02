//! Blockchain.com second-password wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::BlockchainSecond;
use crate::{HashType, HashValue};

pub struct BlockchainSecondExtractor;

const SIGNATURE: &[u8; 3] = b"bs:";
const BLOB_SIZE: usize = 59;
const MAX_DEPTH: usize = 16;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn blob(digest: &[u8], salt: &[u8], iterations: u32) -> Result<BlockchainSecond, ExtractError> {
    if digest.len() != 32 {
        return Err(ExtractError::Invalid(
            "Blockchain second-password digest must be 32 bytes".to_owned(),
        ));
    }
    if salt.len() != 16 {
        return Err(ExtractError::Invalid(
            "Blockchain second-password salt must be 16 bytes".to_owned(),
        ));
    }
    let mut payload = Vec::with_capacity(BLOB_SIZE);
    payload.extend_from_slice(SIGNATURE);
    payload.extend_from_slice(digest);
    payload.extend_from_slice(salt);
    payload.extend_from_slice(&iterations.to_le_bytes());
    let checksum = crc32(&payload);
    payload.extend_from_slice(&checksum.to_le_bytes());
    Ok(BlockchainSecond { payload })
}

fn validate_blob(payload: &[u8]) -> Option<BlockchainSecond> {
    if payload.len() != BLOB_SIZE || &payload[..3] != SIGNATURE {
        return None;
    }
    let expected = u32::from_le_bytes(payload[55..59].try_into().ok()?);
    if crc32(&payload[..55]) != expected {
        return None;
    }
    Some(BlockchainSecond {
        payload: payload.to_vec(),
    })
}

fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return None;
    }
    let joined = parts.concat();
    let bytes = hex::decode(joined).ok()?;
    bytes.as_slice().try_into().ok()
}

fn object(map: &Map<String, Value>) -> Result<Option<BlockchainSecond>, ExtractError> {
    let Some(digest) = map.get("dpasswordhash").and_then(Value::as_str) else {
        return Ok(None);
    };
    if map.get("double_encryption").and_then(Value::as_bool) == Some(false) {
        return Ok(None);
    }
    let digest = hex::decode(digest)
        .map_err(|_| ExtractError::Invalid("invalid Blockchain dpasswordhash".to_owned()))?;
    let shared_key = map
        .get("sharedKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing Blockchain sharedKey".to_owned()))?;
    let salt = uuid_bytes(shared_key)
        .ok_or_else(|| ExtractError::Invalid("invalid Blockchain sharedKey UUID".to_owned()))?;
    let iterations = map
        .get("options")
        .and_then(|options| options.get("pbkdf2_iterations"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ExtractError::Unsupported("missing Blockchain second-password iterations".to_owned())
        })?;
    let iterations = u32::try_from(iterations).map_err(|_| {
        ExtractError::Invalid("Blockchain second-password iterations are too large".to_owned())
    })?;
    if iterations == 0 {
        return Err(ExtractError::Unsupported(
            "Blockchain second-password iterations are unavailable".to_owned(),
        ));
    }
    blob(&digest, &salt, iterations).map(Some)
}

fn collect(
    value: &Value,
    depth: usize,
    hashes: &mut Vec<BlockchainSecond>,
) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::Invalid(
            "Blockchain wallet nesting is too deep".to_owned(),
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
                ExtractError::Invalid(format!("invalid nested Blockchain JSON: {error}"))
            })?;
            collect(&nested, depth + 1, hashes)?;
        }
        _ => {}
    }
    Ok(())
}

fn line_blobs(text: &str, hashes: &mut Vec<BlockchainSecond>) {
    for line in text.lines() {
        let line = line.trim_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '{' | '}' | '[' | ']')
        });
        if line.len() != 80 || !line.starts_with("YnM6") {
            continue;
        }
        let Ok(decoded) = STANDARD.decode(line.as_bytes()) else {
            continue;
        };
        if let Some(hash) = validate_blob(&decoded) {
            hashes.push(hash);
        }
    }
}

fn parse(artifact: &Artifact) -> Result<Vec<BlockchainSecond>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Blockchain wallet is not UTF-8".to_owned()))?;
    let mut hashes = Vec::new();
    match serde_json::from_str::<Value>(text) {
        Ok(document) => collect(&document, 0, &mut hashes)?,
        Err(_) => line_blobs(text, &mut hashes),
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Blockchain second-password wallet found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for BlockchainSecondExtractor {
    fn slug(&self) -> &'static str {
        BlockchainSecond::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Blockchain second-password hash"),
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
