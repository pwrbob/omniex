//! LastPass CLI state extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Lpcli;
use crate::{HashType, HashValue};

pub struct LpcliExtractor;

const VERIFY_LENGTH: u64 = 64;

fn text_member(artifact: &Artifact, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        artifact
            .member(name)
            .and_then(|source| source.read_all().ok())
            .and_then(|data| String::from_utf8(data).ok())
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    })
}

fn username(artifact: &Artifact) -> Option<String> {
    text_member(artifact, &["username", "email"]).map(|name| name.to_lowercase())
}

fn iterations(artifact: &Artifact) -> Option<u32> {
    text_member(artifact, &["iterations", "iter"])
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|iterations| *iterations > 0)
}

fn build(artifact: &Artifact) -> Result<Lpcli, ExtractError> {
    if artifact.primary().len() < VERIFY_LENGTH {
        return Err(ExtractError::Invalid(
            "LastPass CLI verify file is shorter than 64 bytes".to_owned(),
        ));
    }
    let mut verify = [0; VERIFY_LENGTH as usize];
    artifact
        .primary()
        .read_exact_at(0, &mut verify)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    let username = username(artifact).ok_or_else(|| {
        ExtractError::Unsupported(
            "missing LastPass CLI username companion (`username` or `email`)".to_owned(),
        )
    })?;
    let iterations = iterations(artifact).ok_or_else(|| {
        ExtractError::Unsupported("missing LastPass CLI iteration companion".to_owned())
    })?;
    Ok(Lpcli {
        version: 0,
        email: username,
        pin: iterations.to_string(),
        encrypted: verify[32..48].to_vec(),
        digest: verify[48..64]
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid LastPass CLI digest".to_owned()))?,
    })
}

impl Extractor for LpcliExtractor {
    fn slug(&self) -> &'static str {
        Lpcli::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().len() < VERIFY_LENGTH {
            return Probe::No;
        }
        if username(artifact).is_none() || iterations(artifact).is_none() {
            return Probe::Maybe(
                "LastPass CLI verify file needs `username` and `iterations` companions".to_owned(),
            );
        }
        Probe::yes("LastPass CLI verify file")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(build(artifact)?) as Box<dyn HashValue>])
    }
}
