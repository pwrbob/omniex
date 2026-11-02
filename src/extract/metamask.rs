//! MetaMask browser-extension and mobile vault extraction.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{Metamask, MetamaskMobile};
use crate::{HashType, HashValue};

pub struct MetamaskExtractor;
pub struct MetamaskMobileExtractor;

fn document(artifact: &Artifact) -> Result<Value, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let document: Value = serde_json::from_slice(&data)
        .map_err(|error| ExtractError::Invalid(format!("invalid MetaMask JSON: {error}")))?;
    Ok(document.get("vault").cloned().unwrap_or(document))
}

fn base64(value: &Value, field: &str) -> Result<Vec<u8>, ExtractError> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid(format!("missing MetaMask `{field}`")))?;
    STANDARD
        .decode(text)
        .map_err(|_| ExtractError::Invalid(format!("invalid MetaMask `{field}` base64")))
}

fn iterations(document: &Value, default: u32) -> Result<u32, ExtractError> {
    let value = document
        .pointer("/keyMetadata/params/iterations")
        .and_then(Value::as_u64)
        .unwrap_or(default.into());
    u32::try_from(value)
        .map_err(|_| ExtractError::Invalid("MetaMask iteration count is too large".to_owned()))
}

fn mobile_vault(document: &Value) -> bool {
    document
        .get("lib")
        .and_then(|lib| lib.get("original"))
        .is_some()
}

fn parse_desktop(artifact: &Artifact) -> Result<Metamask, ExtractError> {
    let document = document(artifact)?;
    if mobile_vault(&document) {
        return Err(ExtractError::Unsupported(
            "MetaMask mobile vault".to_owned(),
        ));
    }
    if iterations(&document, 10_000)? != 10_000 {
        return Err(ExtractError::Unsupported(
            "non-default MetaMask iteration count".to_owned(),
        ));
    }
    let mut ciphertext = base64(&document, "data")?;
    if ciphertext.len() > 3000 {
        ciphertext.truncate(64);
    }
    let salt = base64(&document, "salt")?;
    let iv = base64(&document, "iv")?;
    let iv = iv
        .as_slice()
        .try_into()
        .map_err(|_| ExtractError::Invalid("MetaMask IV must be 16 bytes".to_owned()))?;
    Ok(Metamask {
        salt,
        iv,
        ciphertext,
    })
}

fn parse_mobile(artifact: &Artifact) -> Result<MetamaskMobile, ExtractError> {
    let document = document(artifact)?;
    if !mobile_vault(&document) {
        return Err(ExtractError::Unsupported(
            "not a MetaMask mobile vault".to_owned(),
        ));
    }
    if iterations(&document, 5_000)? != 5_000 {
        return Err(ExtractError::Unsupported(
            "non-default MetaMask mobile iteration count".to_owned(),
        ));
    }
    let salt = base64(&document, "salt")?;
    let iv = document
        .get("iv")
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid("missing MetaMask mobile `iv`".to_owned()))?;
    let iv = crate::parse::decode_hex(iv, 0)
        .map_err(|error| ExtractError::Invalid(format!("invalid MetaMask mobile `iv`: {error}")))?;
    let iv = iv
        .as_slice()
        .try_into()
        .map_err(|_| ExtractError::Invalid("MetaMask mobile IV must be 16 bytes".to_owned()))?;
    let mut digest = base64(&document, "cipher")?;
    digest.truncate(32);
    Ok(MetamaskMobile { salt, iv, digest })
}

impl Extractor for MetamaskExtractor {
    fn slug(&self) -> &'static str {
        Metamask::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_desktop(artifact) {
            Ok(_) => Probe::yes("MetaMask vault JSON"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![
            Box::new(parse_desktop(artifact)?) as Box<dyn HashValue>
        ])
    }
}

impl Extractor for MetamaskMobileExtractor {
    fn slug(&self) -> &'static str {
        MetamaskMobile::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_mobile(artifact) {
            Ok(_) => Probe::yes("MetaMask mobile vault JSON"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse_mobile(artifact)?) as Box<dyn HashValue>])
    }
}
