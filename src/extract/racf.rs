//! RACF CRACF.TXT extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::Racf;
use crate::{HashType, HashValue};

pub struct RacfExtractor;

fn parse(artifact: &Artifact) -> Result<Vec<Racf>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = std::str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("CRACF.TXT is not UTF-8".to_owned()))?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 {
            continue;
        }
        let salt = fields[0];
        let digest = fields[fields.len() - 1];
        if salt.len() > 8 || digest.len() != 16 {
            continue;
        }
        let digest = parse::decode_hex_field::<8>(digest, 0, "digest")
            .map_err(|error| ExtractError::Invalid(format!("invalid RACF digest: {error}")))?;
        hashes.push(Racf {
            salt: salt.to_owned(),
            digest,
        });
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no RACF records found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for RacfExtractor {
    fn slug(&self) -> &'static str {
        Racf::SLUG
    }
    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("RACF CRACF record"),
            _ => Probe::No,
        }
    }
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
