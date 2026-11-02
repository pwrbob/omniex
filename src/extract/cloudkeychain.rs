//! 1Password cloudkeychain profile extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::CloudkeychainJohn;
use crate::{HashType, HashValue};

pub struct CloudkeychainExtractor;

fn parse(artifact: &Artifact) -> Result<CloudkeychainJohn, ExtractError> {
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
    let iterations = document
        .get("iterations")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ExtractError::Invalid("invalid 1Password iterations".to_owned()))?;
    let master = document
        .get("masterKey")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing 1Password master key".to_owned()))?;
    let master = STANDARD
        .decode(master)
        .map_err(|_| ExtractError::Invalid("invalid 1Password master key base64".to_owned()))?;
    if master.get(..8) != Some(b"opdata01") || master.len() < 32 + 32 {
        return Err(ExtractError::Unsupported(
            "unsupported 1Password master key envelope".to_owned(),
        ));
    }
    let plaintext_length = u64::from_le_bytes(master[8..16].try_into().expect("8 bytes"));
    let iv = &master[16..32];
    let cryptext = &master[32..master.len() - 32];
    let hmac = &master[master.len() - 32..];
    let hmac_data = &master[..master.len() - 32];

    Ok(CloudkeychainJohn {
        data: format!(
            "{len}${salt}${iterations}${mlen}${master}${plaintext}${ivlen}${iv}${clen}${ct}${hlen}${hmac}${dlen}${hdata}",
            len = salt.len(),
            salt = crate::format::hex(&salt),
            iterations = iterations,
            mlen = master.len(),
            master = crate::format::hex(&master),
            plaintext = plaintext_length,
            ivlen = iv.len(),
            iv = crate::format::hex(iv),
            clen = cryptext.len(),
            ct = crate::format::hex(cryptext),
            hlen = hmac.len(),
            hmac = crate::format::hex(hmac),
            dlen = hmac_data.len(),
            hdata = crate::format::hex(hmac_data),
        ),
    })
}

impl Extractor for CloudkeychainExtractor {
    fn slug(&self) -> &'static str {
        CloudkeychainJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("1Password cloudkeychain profile"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
