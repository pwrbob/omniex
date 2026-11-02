//! DiskCryptor volume header extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Diskcryptor;
use omniex::{HashType, HashValue};

pub struct DiskcryptorExtractor;

const HEADER_SIZE: usize = 2048;

fn parse(artifact: &Artifact) -> Result<Diskcryptor, ExtractError> {
    let mut data = vec![0; HEADER_SIZE];
    artifact
        .primary()
        .read_exact_at(0, &mut data)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read DiskCryptor header: {error}"))
        })?;
    if data.iter().all(|byte| *byte == 0) {
        return Err(ExtractError::Unsupported(
            "DiskCryptor volume header is empty".to_owned(),
        ));
    }
    Ok(Diskcryptor { version: 0, data })
}

impl Extractor for DiskcryptorExtractor {
    fn slug(&self) -> &'static str {
        Diskcryptor::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::maybe("DiskCryptor volume header has no plaintext signature"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
