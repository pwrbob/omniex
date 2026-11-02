//! eCryptfs wrapped-passphrase extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::Ecryptfs;
use crate::{HashType, HashValue};

pub struct EcryptfsExtractor;

const DEFAULT_SALT: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

fn parse(artifact: &Artifact) -> Result<Ecryptfs, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.get(..2) == Some(b":\x02") {
        return parse_version_two(&data);
    }
    parse_version_one(&data)
}

fn parse_version_two(data: &[u8]) -> Result<Ecryptfs, ExtractError> {
    let salt = data
        .get(2..10)
        .ok_or_else(|| ExtractError::Invalid("truncated eCryptfs salt".to_owned()))?;
    let signature = data
        .get(10..26)
        .ok_or_else(|| ExtractError::Invalid("truncated eCryptfs signature".to_owned()))?;
    let signature = std::str::from_utf8(signature)
        .map_err(|_| ExtractError::Invalid("invalid eCryptfs signature text".to_owned()))?;
    let signature = parse::decode_hex_field::<8>(signature, 10, "signature")
        .map_err(|error| ExtractError::Invalid(format!("invalid eCryptfs signature: {error}")))?;
    Ok(Ecryptfs {
        version: 0,
        flags: 1,
        salt: salt.try_into().expect("8-byte salt"),
        signature,
    })
}

fn parse_version_one(data: &[u8]) -> Result<Ecryptfs, ExtractError> {
    if data.len() != 16 {
        return Err(ExtractError::Unsupported(
            "not an eCryptfs version 1 wrapped passphrase".to_owned(),
        ));
    }
    let signature = std::str::from_utf8(data)
        .map_err(|_| ExtractError::Unsupported("not an eCryptfs wrapped passphrase".to_owned()))?;
    let signature = parse::decode_hex_field::<8>(signature, 0, "signature")
        .map_err(|error| ExtractError::Invalid(format!("invalid eCryptfs signature: {error}")))?;
    Ok(Ecryptfs {
        version: 0,
        flags: 1,
        salt: DEFAULT_SALT,
        signature,
    })
}

impl Extractor for EcryptfsExtractor {
    fn slug(&self) -> &'static str {
        Ecryptfs::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(_) => return Probe::No,
        };
        if data.get(..2) != Some(b":\x02") {
            return Probe::No;
        }
        match parse_version_two(&data) {
            Ok(_) => Probe::yes("eCryptfs version 2 wrapped passphrase"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
