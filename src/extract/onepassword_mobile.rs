//! 1Password 8 mobile keychain account extraction.

use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::OnepasswordMobile;
use crate::{HashType, HashValue};

pub struct OnepasswordMobileExtractor;

fn string<'a>(account: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| account.get(*name).and_then(Value::as_str))
}

fn number(account: &Value, names: &[&str]) -> Option<u32> {
    names
        .iter()
        .find_map(|name| account.get(*name).and_then(Value::as_u64))
        .and_then(|value| u32::try_from(value).ok())
}

fn decode(value: &str, field: &str) -> Result<Vec<u8>, ExtractError> {
    crate::parse::decode_hex(value, 0)
        .map_err(|_| ExtractError::Invalid(format!("invalid 1Password `{field}` hex")))
}

fn account(value: &Value) -> Result<OnepasswordMobile, ExtractError> {
    let email = string(value, &["email"])
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ExtractError::Invalid("missing 1Password account email".to_owned()))?;
    let salt = string(value, &["hkdf_salt", "hkdfSalt"])
        .ok_or_else(|| ExtractError::Invalid("missing 1Password HKDF salt".to_owned()))?;
    let salt = decode(salt, "hkdf_salt")?;
    if salt.len() != 32 {
        return Err(ExtractError::Invalid(
            "1Password HKDF salt must be 32 bytes".to_owned(),
        ));
    }
    let key = string(value, &["hkdf_key", "hkdfKey"])
        .ok_or_else(|| ExtractError::Invalid("missing 1Password HKDF key".to_owned()))?;
    let key = decode(key, "hkdf_key")?;
    if key.len() != 32 {
        return Err(ExtractError::Invalid(
            "1Password HKDF key must be 32 bytes".to_owned(),
        ));
    }
    let iterations = number(value, &["iterations", "kdfIterations", "kdf_iterations"])
        .filter(|iterations| *iterations > 0)
        .ok_or_else(|| ExtractError::Invalid("invalid 1Password iterations".to_owned()))?;

    let sym = value.get("enc_sym_key").or_else(|| value.get("encSymKey"));
    let (iv, ciphertext, tag) = if let Some(sym) = sym {
        let iv = string(sym, &["iv"])
            .ok_or_else(|| ExtractError::Invalid("missing 1Password symkey IV".to_owned()))?;
        let data = string(sym, &["data", "ciphertext"])
            .ok_or_else(|| ExtractError::Invalid("missing 1Password symkey data".to_owned()))?;
        let data = decode(data, "enc_sym_key.data")?;
        if data.len() <= 16 {
            return Err(ExtractError::Invalid(
                "1Password symkey data is too short".to_owned(),
            ));
        }
        let split = data.len() - 16;
        (iv, data[..split].to_vec(), data[split..].to_vec())
    } else {
        let iv = string(value, &["iv"])
            .ok_or_else(|| ExtractError::Invalid("missing 1Password IV".to_owned()))?;
        let ciphertext = string(value, &["ciphertext", "data"])
            .ok_or_else(|| ExtractError::Invalid("missing 1Password ciphertext".to_owned()))?;
        let tag = string(value, &["tag"])
            .ok_or_else(|| ExtractError::Invalid("missing 1Password tag".to_owned()))?;
        (iv, decode(ciphertext, "ciphertext")?, decode(tag, "tag")?)
    };

    let iv = decode(iv, "iv")?;
    if !matches!(iv.len(), 12 | 16) {
        return Err(ExtractError::Invalid(
            "1Password IV must be 12 or 16 bytes".to_owned(),
        ));
    }
    if ciphertext.is_empty() {
        return Err(ExtractError::Invalid(
            "1Password ciphertext is empty".to_owned(),
        ));
    }
    if tag.len() != 16 {
        return Err(ExtractError::Invalid(
            "1Password tag must be 16 bytes".to_owned(),
        ));
    }

    Ok(OnepasswordMobile {
        email: email.to_owned(),
        hkdf_salt: crate::format::hex(&salt),
        hkdf_key: crate::format::hex(&key),
        iterations,
        iv: crate::format::hex(&iv),
        ciphertext: crate::format::hex(&ciphertext),
        tag: crate::format::hex(&tag),
    })
}

fn accounts(document: &Value) -> Option<&[Value]> {
    if let Some(list) = document.as_array() {
        return Some(list);
    }
    for name in ["accounts", "account"] {
        if let Some(list) = document.get(name).and_then(Value::as_array) {
            return Some(list);
        }
    }
    Some(std::slice::from_ref(document))
}

fn parse(artifact: &Artifact) -> Result<Vec<OnepasswordMobile>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let document: Value = serde_json::from_slice(&data)
        .map_err(|error| ExtractError::Invalid(format!("invalid 1Password JSON: {error}")))?;
    let list = accounts(&document)
        .ok_or_else(|| ExtractError::Unsupported("missing 1Password accounts".to_owned()))?;
    if list.is_empty() {
        return Err(ExtractError::Unsupported(
            "1Password account list is empty".to_owned(),
        ));
    }
    list.iter().map(account).collect()
}

impl Extractor for OnepasswordMobileExtractor {
    fn slug(&self) -> &'static str {
        OnepasswordMobile::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("1Password mobile keychain accounts"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
