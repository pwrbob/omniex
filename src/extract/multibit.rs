//! MultiBit Classic and HD wallet extraction.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{Multibit, MultibitHd};
use crate::{HashType, HashValue};

pub struct MultibitKeyExtractor;
pub struct MultibitHdExtractor;

fn decoded_key(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let compact = text.split_ascii_whitespace().collect::<String>();
    if compact.len() < 64 {
        return None;
    }
    STANDARD.decode(&compact[..64]).ok()
}

impl Extractor for MultibitKeyExtractor {
    fn slug(&self) -> &'static str {
        Multibit::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match decoded_key(&data) {
            Some(key) if key.starts_with(b"Salted__") && key.len() >= 48 => {
                Probe::yes("MultiBit Classic key file")
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let key = decoded_key(&data)
            .filter(|key| key.starts_with(b"Salted__") && key.len() >= 48)
            .ok_or_else(|| ExtractError::Unsupported("not a MultiBit Classic key".to_owned()))?;
        Ok(vec![Box::new(Multibit {
            version: 1,
            salt: key[8..16].try_into().expect("8-byte salt"),
            digest: key[16..48].try_into().expect("32-byte encrypted key"),
        }) as Box<dyn HashValue>])
    }
}

impl Extractor for MultibitHdExtractor {
    fn slug(&self) -> &'static str {
        MultibitHd::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().len() < 32 {
            return Probe::No;
        }
        if artifact
            .label()
            .to_ascii_lowercase()
            .ends_with(".wallet.aes")
            || artifact.label().to_ascii_lowercase().ends_with(".aes")
        {
            Probe::maybe("MultiBit HD wallet file extension")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let mut data = [0; 32];
        artifact
            .primary()
            .read_exact_at(0, &mut data)
            .map_err(|error| {
                ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
            })?;
        Ok(vec![Box::new(MultibitHd {
            version: 2,
            salt: data[..16].try_into().expect("16-byte IV"),
            encrypted: data[16..32].try_into().expect("16-byte block"),
            digest: data[..16].try_into().expect("16-byte block"),
        }) as Box<dyn HashValue>])
    }
}
