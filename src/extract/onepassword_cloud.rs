//! 1Password cloudkeychain hashcat serialization extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::OnepasswordCloud;
use crate::{HashType, HashValue};

pub struct OnepasswordCloudExtractor;

fn profile(artifact: &Artifact) -> Result<OnepasswordCloud, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("1Password profile.js is not UTF-8".to_owned()))?;
    let start = text.find('{').ok_or_else(|| {
        ExtractError::Unsupported("no JSON object in 1Password profile.js".to_owned())
    })?;
    let end = text
        .rfind('}')
        .ok_or_else(|| ExtractError::Invalid("truncated 1Password profile JSON".to_owned()))?;
    let document: Value = serde_json::from_str(&text[start..=end]).map_err(|error| {
        ExtractError::Invalid(format!("invalid 1Password profile JSON: {error}"))
    })?;
    let salt = document
        .get("salt")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing 1Password profile salt".to_owned()))?;
    let salt = STANDARD
        .decode(salt)
        .map_err(|_| ExtractError::Invalid("invalid 1Password salt base64".to_owned()))?;
    if salt.is_empty() {
        return Err(ExtractError::Invalid("1Password salt is empty".to_owned()));
    }
    let iterations = document
        .get("iterations")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| ExtractError::Invalid("invalid 1Password iterations".to_owned()))?;
    let master = document
        .get("masterKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing 1Password master key".to_owned()))?;
    let master = STANDARD
        .decode(master)
        .map_err(|_| ExtractError::Invalid("invalid 1Password master key base64".to_owned()))?;
    if master.len() < 80 || master.get(..8) != Some(b"opdata01") {
        return Err(ExtractError::Unsupported(
            "unsupported 1Password master key envelope".to_owned(),
        ));
    }
    let split = master.len() - 32;
    let digest = master[split..]
        .try_into()
        .map_err(|_| ExtractError::Invalid("invalid 1Password HMAC length".to_owned()))?;
    Ok(OnepasswordCloud {
        digest,
        salt,
        iterations,
        data: master[..split].to_vec(),
    })
}

impl Extractor for OnepasswordCloudExtractor {
    fn slug(&self) -> &'static str {
        OnepasswordCloud::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match profile(artifact) {
            Ok(_) => Probe::yes("1Password cloudkeychain profile"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(profile(artifact)?) as Box<dyn HashValue>])
    }
}
