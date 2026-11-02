//! macOS local account PBKDF2-SHA512 password plist extraction.

use super::macos_sha1::plist;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::MacosPbkdf2Sha512;
use crate::{HashType, HashValue};

const SALT_LENGTH: usize = 32;
const ENTROPY_LENGTH: usize = 64;

fn parse(artifact: &Artifact) -> Result<MacosPbkdf2Sha512, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let shadow = plist::shadow_hash_dictionary(&data)?;
    let entry = shadow.get("SALTED-SHA512-PBKDF2").ok_or_else(|| {
        ExtractError::Unsupported("no SALTED-SHA512-PBKDF2 shadow hash".to_owned())
    })?;
    let salt = entry
        .get("salt")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| ExtractError::Invalid("missing PBKDF2 salt".to_owned()))?;
    let entropy = entry
        .get("entropy")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| ExtractError::Invalid("missing PBKDF2 entropy".to_owned()))?;
    let iterations = entry
        .get("iterations")
        .and_then(plist::Value::as_int)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| ExtractError::Invalid("invalid PBKDF2 iteration count".to_owned()))?;
    if salt.len() != SALT_LENGTH {
        return Err(ExtractError::Invalid(
            "macOS PBKDF2 salt must be 32 bytes".to_owned(),
        ));
    }
    if entropy.len() != ENTROPY_LENGTH {
        return Err(ExtractError::Invalid(
            "macOS PBKDF2 entropy must be 64 bytes".to_owned(),
        ));
    }
    Ok(MacosPbkdf2Sha512 {
        iterations,
        salt: salt.to_vec(),
        digest: entropy.to_vec(),
    })
}

pub struct MacosPbkdf2Sha512Extractor;

impl Extractor for MacosPbkdf2Sha512Extractor {
    fn slug(&self) -> &'static str {
        MacosPbkdf2Sha512::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("macOS PBKDF2-SHA512 shadow hash"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
