//! Legacy Kerberos 5 database extraction for etypes 1, 2, and 3.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::Krb5DbOld;
use omniex::{HashType, HashValue};

use super::krb5db17::{probe_for, records};

pub struct Krb5DbOldExtractor;

impl Extractor for Krb5DbOldExtractor {
    fn slug(&self) -> &'static str {
        Krb5DbOld::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_for(artifact, &[1, 2, 3])
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let records = records(artifact, &[1, 2, 3])?;
        let mut extracted = Vec::with_capacity(records.len());
        for record in records {
            let digest: [u8; 8] = record.key.try_into().map_err(|_| {
                ExtractError::Invalid("legacy Kerberos database key is not 8 bytes".to_owned())
            })?;
            extracted.push(Box::new(Krb5DbOld {
                etype: record.etype,
                username: record.username,
                realm: record.realm,
                digest,
            }) as Box<dyn HashValue>);
        }
        Ok(extracted)
    }
}
