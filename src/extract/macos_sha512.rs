//! macOS local account SHA512 password plist extraction.

use super::macos_sha1::plist;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::MacosSha512;
use crate::{HashType, HashValue};

const SHADOW_HASH_LENGTH: usize = 68;

fn parse(artifact: &Artifact) -> Result<MacosSha512, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let shadow = plist::shadow_hash_dictionary(&data)?;
    let blob = shadow
        .get("SALTED-SHA512")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| ExtractError::Unsupported("no SALTED-SHA512 shadow hash".to_owned()))?;
    if blob.len() != SHADOW_HASH_LENGTH {
        return Err(ExtractError::Invalid(
            "macOS SHA512 shadow hash has the wrong length".to_owned(),
        ));
    }
    Ok(MacosSha512 {
        salt: blob[..4].try_into().expect("four-byte salt"),
        digest: blob[4..].try_into().expect("sixty-four-byte digest"),
    })
}

pub struct MacosSha512Extractor;

impl Extractor for MacosSha512Extractor {
    fn slug(&self) -> &'static str {
        MacosSha512::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("macOS SHA512 shadow hash"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
