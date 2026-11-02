//! Kerberos 5 etype 17 TGS-REP extraction.

use std::collections::BTreeSet;

use super::krb5asrep23::kerberos;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5Tgs17;
use crate::{HashType, HashValue};

pub struct Krb5Tgs17Extractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5Tgs17>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in kerberos::messages(artifact)? {
        if message.kind != kerberos::Kind::TgsRep
            || message.etype != 17
            || message.cipher.len() <= 12
        {
            continue;
        }
        let Some(spn) = message.spn else {
            continue;
        };
        if spn.is_empty() {
            continue;
        }
        let split = message.cipher.len() - 12;
        let checksum: [u8; 12] = message
            .cipher
            .get(split..)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ExtractError::Invalid("short Kerberos checksum".to_owned()))?;
        records.insert((
            message.username,
            message.realm,
            checksum,
            message.cipher[..split].to_vec(),
        ));
    }
    Ok(records
        .into_iter()
        .map(|(username, realm, checksum, ciphertext)| Krb5Tgs17 {
            username,
            realm,
            checksum,
            ciphertext,
        })
        .collect())
}

impl Extractor for Krb5Tgs17Extractor {
    fn slug(&self) -> &'static str {
        Krb5Tgs17::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        kerberos::probe_artifact(artifact, kerberos::Kind::TgsRep, 17)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos TGS-REP etype 17 messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
