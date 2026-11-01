//! Electrum wallet extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Electrum;
use crate::{HashType, HashValue};

pub struct ElectrumExtractor;

fn parse(artifact: &Artifact) -> Result<Electrum, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Electrum wallet is not UTF-8".to_owned()))?;
    let wallet: Value = serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid Electrum JSON: {error}")))?;
    if wallet.get("use_encryption").and_then(Value::as_bool) == Some(false) {
        return Err(ExtractError::Unsupported(
            "Electrum wallet is not encrypted".to_owned(),
        ));
    }
    let (version, encoded, offset) = if let Some(keystore) = wallet.get("keystore") {
        match keystore.get("type").and_then(Value::as_str) {
            Some("bip32") => (2, keystore.get("xprv").and_then(Value::as_str), 0usize),
            Some("old") => (1, keystore.get("seed").and_then(Value::as_str), 0usize),
            Some("imported") => {
                let key = keystore
                    .get("keypairs")
                    .and_then(Value::as_object)
                    .and_then(|keys| keys.values().find_map(Value::as_str));
                (3, key, 64)
            }
            _ => {
                return Err(ExtractError::Unsupported(
                    "unsupported Electrum keystore".to_owned(),
                ));
            }
        }
    } else if let Some(xprv) = wallet
        .get("master_private_keys")
        .and_then(Value::as_object)
        .and_then(|keys| keys.values().find_map(Value::as_str))
    {
        (2, Some(xprv), 0)
    } else {
        return Err(ExtractError::Unsupported(
            "no Electrum encrypted key found".to_owned(),
        ));
    };
    let encoded = encoded
        .ok_or_else(|| ExtractError::Unsupported("missing Electrum encrypted key".to_owned()))?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ExtractError::Invalid("invalid Electrum key base64".to_owned()))?;
    let expected = match version {
        1 => 64,
        2 => 128,
        3 => 80,
        _ => unreachable!(),
    };
    if decoded.len() != expected {
        return Err(ExtractError::Invalid(
            "unexpected Electrum key length".to_owned(),
        ));
    }
    let iv = &decoded[offset..offset + 16];
    let data = &decoded[offset + 16..offset + 32];
    Ok(Electrum {
        version,
        salt: crate::format::hex(iv),
        data: data.to_vec(),
        mac: Vec::new(),
    })
}

impl Extractor for ElectrumExtractor {
    fn slug(&self) -> &'static str {
        Electrum::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("encrypted Electrum wallet"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
