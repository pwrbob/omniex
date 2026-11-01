//! Dashlane database extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Dashlane;
use crate::{HashType, HashValue};

pub struct DashlaneExtractor;

fn data(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let secure_archive = str::from_utf8(&data)
        .ok()
        .and_then(|text| text.lines().position(|line| line.contains("Data BEGIN")));
    let data: Vec<u8> = if let Some(index) = secure_archive {
        let line = str::from_utf8(&data)
            .ok()
            .and_then(|text| text.lines().nth(index + 1))
            .ok_or_else(|| {
                ExtractError::Invalid("missing Dashlane secure archive data".to_owned())
            })?;
        STANDARD
            .decode(line.trim())
            .map_err(|_| {
                ExtractError::Invalid("invalid Dashlane secure archive base64".to_owned())
            })?
            .into_iter()
            .take(256)
            .collect()
    } else {
        data.into_iter().take(256).collect()
    };
    if data.len() < 32 {
        return Err(ExtractError::Invalid(
            "Dashlane database is shorter than 32 bytes".to_owned(),
        ));
    }
    Ok(data)
}

fn secure_archive(artifact: &Artifact) -> bool {
    let Ok(data) = artifact.primary().read_all() else {
        return false;
    };
    let Ok(text) = str::from_utf8(&data) else {
        return false;
    };
    let Some(index) = text.lines().position(|line| line.contains("Data BEGIN")) else {
        return false;
    };
    text.lines()
        .nth(index + 1)
        .and_then(|line| STANDARD.decode(line.trim()).ok())
        .is_some_and(|data| data.len() >= 32)
}

impl Extractor for DashlaneExtractor {
    fn slug(&self) -> &'static str {
        Dashlane::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if secure_archive(artifact) {
            return Probe::yes("Dashlane secure archive");
        }
        let label = artifact.label().to_ascii_lowercase();
        if (label.ends_with(".aes") || label.ends_with(".dash")) && artifact.primary().len() >= 32 {
            Probe::maybe("Dashlane database file extension")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = data(artifact)?;
        let salt = crate::format::hex(&data[..32]);
        let (version, data) = if data[32..].starts_with(b"KWC3") {
            (1, &data[36..])
        } else {
            (0, &data[32..])
        };
        Ok(vec![Box::new(Dashlane {
            fields: format!(
                "{version}*{salt}*{}*{}",
                data.len(),
                crate::format::hex(data)
            ),
        }) as Box<dyn HashValue>])
    }
}
