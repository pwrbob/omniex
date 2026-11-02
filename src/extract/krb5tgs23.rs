//! Kerberos 5 etype 23 TGS-REP extraction.

use std::collections::BTreeSet;

use super::krb5asrep23::kerberos;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5Tgs23;
use crate::{HashType, HashValue};

pub struct Krb5Tgs23Extractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5Tgs23>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in kerberos::messages(artifact)? {
        if message.kind != kerberos::Kind::TgsRep
            || message.etype != 23
            || message.cipher.len() <= 16
        {
            continue;
        }
        let Some(spn) = message.spn else {
            continue;
        };
        if spn.is_empty() {
            continue;
        }
        let checksum: [u8; 16] = message
            .cipher
            .get(..16)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ExtractError::Invalid("short Kerberos checksum".to_owned()))?;
        records.insert((
            message.username,
            message.realm,
            spn,
            checksum,
            message.cipher[16..].to_vec(),
        ));
    }
    Ok(records
        .into_iter()
        .map(|(username, realm, spn, checksum, ciphertext)| Krb5Tgs23 {
            username,
            realm,
            spn,
            checksum,
            ciphertext,
        })
        .collect())
}

impl Extractor for Krb5Tgs23Extractor {
    fn slug(&self) -> &'static str {
        Krb5Tgs23::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        kerberos::probe_artifact(artifact, kerberos::Kind::TgsRep, 23)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos TGS-REP etype 23 messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
