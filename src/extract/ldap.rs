//! LDAP LDIF password attribute extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{LdapSha1, LdapSsha1, LdapSsha256, LdapSsha512};
use crate::{HashType, HashValue, Parse, ParseOptions};

pub struct LdapSha1Extractor;
pub struct LdapSsha1Extractor;
pub struct LdapSsha256Extractor;
pub struct LdapSsha512Extractor;

fn values(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("LDIF file is not UTF-8".to_owned()))?;
    let mut values = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("userPassword:") else {
            continue;
        };
        let value = if let Some(encoded) = rest.strip_prefix(':') {
            STANDARD
                .decode(encoded.trim())
                .ok()
                .and_then(|value| String::from_utf8(value).ok())
        } else {
            Some(rest.trim().to_owned())
        };
        if let Some(value) = value {
            values.push(value);
        }
    }
    Ok(values)
}

fn extract<T: Parse>(artifact: &Artifact) -> Result<Vec<T>, ExtractError> {
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for value in values(artifact)? {
        if let Ok(hash) = T::parse(&value, &opts) {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no matching LDAP password attributes found".to_owned(),
        ));
    }
    Ok(hashes)
}

fn probe<T: Parse>(artifact: &Artifact) -> Probe {
    match extract::<T>(artifact) {
        Ok(_) => Probe::yes("LDAP LDIF password attribute"),
        Err(_) => Probe::No,
    }
}

impl Extractor for LdapSha1Extractor {
    fn slug(&self) -> &'static str {
        LdapSha1::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        probe::<LdapSha1>(artifact)
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract::<LdapSha1>(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}

impl Extractor for LdapSsha1Extractor {
    fn slug(&self) -> &'static str {
        LdapSsha1::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        probe::<LdapSsha1>(artifact)
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract::<LdapSsha1>(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}

impl Extractor for LdapSsha256Extractor {
    fn slug(&self) -> &'static str {
        LdapSsha256::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        probe::<LdapSsha256>(artifact)
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract::<LdapSsha256>(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}

impl Extractor for LdapSsha512Extractor {
    fn slug(&self) -> &'static str {
        LdapSsha512::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        probe::<LdapSsha512>(artifact)
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract::<LdapSsha512>(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
