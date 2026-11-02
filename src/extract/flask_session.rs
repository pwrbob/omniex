//! Flask signed session cookie extraction.

use std::collections::HashSet;
use std::str;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::FlaskSession;
use crate::{HashType, HashValue};

pub struct FlaskSessionExtractor;

fn decode(segment: &str) -> Option<Vec<u8>> {
    if segment.is_empty() {
        return None;
    }
    URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()
}

fn cookie(candidate: &str) -> Option<FlaskSession> {
    let parts = candidate.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let payload = decode(parts[0])?;
    if !payload.starts_with(b"{") {
        return None;
    }
    if !serde_json::from_slice::<Value>(&payload).ok()?.is_object() {
        return None;
    }
    let timestamp = decode(parts[1])?;
    if !(3..=8).contains(&timestamp.len()) || timestamp.iter().all(|byte| *byte == 0) {
        return None;
    }
    if decode(parts[2])?.len() != 20 {
        return None;
    }
    Some(FlaskSession {
        payload: parts[0].to_owned(),
        timestamp: parts[1].to_owned(),
        signature: parts[2].to_owned(),
    })
}

fn candidates(text: &str) -> Vec<FlaskSession> {
    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    for raw in text.split(|character: char| {
        character.is_whitespace() || matches!(character, ';' | '"' | '\'' | ',' | '<' | '>')
    }) {
        let token = raw.rsplit('=').next().unwrap_or(raw);
        let token = token.trim_matches(|character: char| {
            matches!(character, '&' | ':' | '\\' | ')' | '(' | '[' | ']')
        });
        let Some(hash) = cookie(token) else {
            continue;
        };
        let rendered = format!("{}.{}.{}", hash.payload, hash.timestamp, hash.signature);
        if seen.insert(rendered) {
            hashes.push(hash);
        }
    }
    hashes
}

fn parse(artifact: &Artifact) -> Result<Vec<FlaskSession>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Flask session cookie file is not UTF-8".to_owned()))?;
    let hashes = candidates(text);
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Flask signed session cookie found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for FlaskSessionExtractor {
    fn slug(&self) -> &'static str {
        FlaskSession::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Flask signed session cookie"),
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
