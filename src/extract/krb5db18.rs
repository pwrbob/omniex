//! Kerberos 5 etype 18 database extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Krb5Db18;
use omniex::{HashType, HashValue};

use super::krb5db17::{probe_for, records};

pub struct Krb5Db18Extractor;

impl Extractor for Krb5Db18Extractor {
    fn slug(&self) -> &'static str {
        Krb5Db18::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_for(artifact, &[18])
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let records = records(artifact, &[18])?;
        let mut extracted = Vec::with_capacity(records.len());
        for record in records {
            let digest: [u8; 32] = record.key.try_into().map_err(|_| {
                ExtractError::Invalid("Kerberos etype 18 key is not 32 bytes".to_owned())
            })?;
            extracted.push(Box::new(Krb5Db18 {
                username: record.username,
                realm: record.realm,
                digest,
            }) as Box<dyn HashValue>);
        }
        Ok(extracted)
    }
}
