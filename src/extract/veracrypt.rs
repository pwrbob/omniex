//! VeraCrypt volume header extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::VeraCrypt;
use omniex::{HashType, HashValue};

pub struct VeraCryptExtractor;

const HEADER_SIZE: usize = 512;
const SALT_SIZE: usize = 64;

fn parse(artifact: &Artifact) -> Result<VeraCrypt, ExtractError> {
    let mut header = [0u8; HEADER_SIZE];
    artifact
        .primary()
        .read_exact_at(0, &mut header)
        .map_err(|error| ExtractError::Invalid(format!("cannot read VeraCrypt header: {error}")))?;
    if header.iter().all(|byte| *byte == 0) {
        return Err(ExtractError::Unsupported(
            "VeraCrypt volume header is empty".to_owned(),
        ));
    }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&header[..SALT_SIZE]);
    let mut data = [0u8; 448];
    data.copy_from_slice(&header[SALT_SIZE..]);
    Ok(VeraCrypt { salt, data })
}

impl Extractor for VeraCryptExtractor {
    fn slug(&self) -> &'static str {
        VeraCrypt::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::maybe("VeraCrypt volume header has no signature"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
