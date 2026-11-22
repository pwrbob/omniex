//! Password Safe v2 database extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::PwsafeV2;
use crate::{HashType, HashValue};

const HEADER_LENGTH: u64 = 168;
const MIN_LENGTH: u64 = HEADER_LENGTH + 8;

pub struct PwsafeV2Extractor;

fn has_v2_shape(artifact: &Artifact) -> bool {
    let source = artifact.primary();
    let len = source.len();
    if len < MIN_LENGTH || !(len - HEADER_LENGTH).is_multiple_of(8) {
        return false;
    }
    let mut magic = [0; 4];
    match source.read_at(0, &mut magic) {
        Ok(4) => &magic != b"PWS3",
        _ => false,
    }
}

impl Extractor for PwsafeV2Extractor {
    fn slug(&self) -> &'static str {
        PwsafeV2::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let label = artifact.label().to_ascii_lowercase();
        if !label.ends_with(".dat") {
            return Probe::No;
        }
        if has_v2_shape(artifact) {
            Probe::maybe("Password Safe v2 database header")
        } else {
            Probe::No
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let source = artifact.primary();
        let len = source.len();
        if len < HEADER_LENGTH {
            return Err(ExtractError::Invalid(format!(
                "Password Safe v2 header is truncated: {len} bytes"
            )));
        }
        let mut data = vec![0; HEADER_LENGTH as usize];
        source.read_exact_at(0, &mut data).map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        if &data[..4] == b"PWS3" {
            return Err(ExtractError::Unsupported(
                "Password Safe v3 database".to_owned(),
            ));
        }
        Ok(vec![Box::new(PwsafeV2 {
            random: data[0..8].try_into().expect("8-byte salt"),
            digest: data[8..28].try_into().expect("20-byte digest"),
            reserved_salt: data[28..48].try_into().expect("20-byte reserved salt"),
            reserved_iv: data[48..56].try_into().expect("8-byte reserved IV"),
            payload: data[56..].to_vec(),
        }) as Box<dyn HashValue>])
    }
}
