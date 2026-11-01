//! JSON Web Token extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Jwt;
use crate::{HashType, HashValue, Parse, ParseOptions};

pub struct JwtExtractor;

fn token(artifact: &Artifact) -> Result<Jwt, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("JWT file is not UTF-8".to_owned()))?;
    Jwt::parse(text.trim(), &ParseOptions::default())
        .map_err(|error| ExtractError::Invalid(format!("invalid JWT: {error}")))
}

fn decode(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()
}

fn classify(jwt: &Jwt) -> Probe {
    let Some(header) =
        decode(&jwt.header).and_then(|data| serde_json::from_slice::<Value>(&data).ok())
    else {
        return Probe::No;
    };
    let Some(payload) =
        decode(&jwt.payload).and_then(|data| serde_json::from_slice::<Value>(&data).ok())
    else {
        return Probe::No;
    };
    if !header.is_object() || !payload.is_object() {
        return Probe::No;
    }
    let Some(algorithm) = header.get("alg").and_then(Value::as_str) else {
        return Probe::No;
    };
    let signature_length = decode(&jwt.signature)
        .map(|signature| signature.len())
        .unwrap_or(0);
    let expected = match algorithm {
        "HS256" => 32,
        "HS384" => 48,
        "HS512" => 64,
        _ => {
            return Probe::maybe(format!(
                "JWT structure with unsupported signing algorithm `{algorithm}`"
            ));
        }
    };
    if signature_length != expected {
        return Probe::No;
    }
    Probe::yes("JWT HMAC header, payload, and signature structure")
}

impl Extractor for JwtExtractor {
    fn slug(&self) -> &'static str {
        Jwt::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match token(artifact) {
            Ok(jwt) => classify(&jwt),
            Err(ExtractError::Invalid(_)) => Probe::No,
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(token(artifact)?) as Box<dyn HashValue>])
    }
}
