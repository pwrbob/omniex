//! Password Safe v3 extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{Pwsafe, PwsafeV3};
use crate::{HashType, HashValue};

const HEADER_LENGTH: u64 = 360;
const MIN_HEADER: u64 = 72;

fn header(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    let len = artifact.primary().len();
    if len < HEADER_LENGTH {
        return Err(ExtractError::Invalid(format!(
            "Password Safe v3 header is truncated: {len} bytes"
        )));
    }
    let mut data = vec![0; HEADER_LENGTH as usize];
    artifact
        .primary()
        .read_exact_at(0, &mut data)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    if &data[..4] != b"PWS3" {
        return Err(ExtractError::Unsupported(
            "missing Password Safe `PWS3` signature".to_owned(),
        ));
    }
    Ok(data)
}

fn fields(data: &[u8]) -> ([u8; 32], u32, [u8; 32]) {
    let salt = data[4..36].try_into().expect("32-byte salt");
    let iterations = LittleEndian::read_u32(&data[36..40]);
    let digest = data[40..72].try_into().expect("32-byte digest");
    (salt, iterations, digest)
}

pub struct PwsafeV3Extractor;

impl Extractor for PwsafeV3Extractor {
    fn slug(&self) -> &'static str {
        PwsafeV3::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        if source.len() < HEADER_LENGTH {
            return Probe::No;
        }
        let mut magic = [0; 4];
        match source.read_at(0, &mut magic) {
            Ok(4) if &magic == b"PWS3" => Probe::yes("Password Safe v3 header"),
            Ok(_) => Probe::No,
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = header(artifact)?;
        let (salt, iterations, digest) = fields(&data);
        Ok(vec![Box::new(PwsafeV3 {
            signature: "PWS3".to_owned(),
            salt,
            iterations,
            digest,
            payload: data[72..].to_vec(),
        }) as Box<dyn HashValue>])
    }
}

pub struct PwsafeExtractor;

impl Extractor for PwsafeExtractor {
    fn slug(&self) -> &'static str {
        Pwsafe::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        if source.len() < MIN_HEADER {
            return Probe::No;
        }
        let mut magic = [0; 4];
        match source.read_at(0, &mut magic) {
            Ok(4) if &magic == b"PWS3" => Probe::yes("Password Safe v3 header"),
            Ok(_) => Probe::No,
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = header(artifact)?;
        let (salt, iterations, digest) = fields(&data);
        Ok(vec![Box::new(Pwsafe {
            version: 3,
            salt,
            iterations,
            digest,
        }) as Box<dyn HashValue>])
    }
}
