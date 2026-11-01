//! SSH hashed known_hosts extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::KnownHosts;
use crate::{HashType, HashValue};

pub struct KnownHostsExtractor;

fn decode_20(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 20)
}

fn hashed_entry(line: &str) -> Option<(&str, &str)> {
    let token = line.trim().split_ascii_whitespace().next()?;
    let rest = token.strip_prefix("|1|")?;
    let (salt, digest) = rest.split_once('|')?;
    if !decode_20(salt) || !decode_20(digest) {
        return None;
    }
    Some((salt, digest))
}

impl Extractor for KnownHostsExtractor {
    fn slug(&self) -> &'static str {
        KnownHosts::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        let Ok(text) = str::from_utf8(&data) else {
            return Probe::No;
        };
        if text.lines().any(|line| hashed_entry(line).is_some()) {
            Probe::yes("hashed SSH known_hosts entry")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let text = str::from_utf8(&data)
            .map_err(|_| ExtractError::Invalid("known_hosts file is not valid UTF-8".to_owned()))?;

        let mut hashes = Vec::new();
        for line in text.lines() {
            if let Some((salt, digest)) = hashed_entry(line) {
                hashes.push(Box::new(KnownHosts {
                    salt: salt.to_owned(),
                    digest: digest.to_owned(),
                }) as Box<dyn HashValue>);
            }
        }

        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no hashed known_hosts entries found".to_owned(),
            ));
        }
        Ok(hashes)
    }
}
