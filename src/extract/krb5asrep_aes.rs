//! Kerberos 5 etype 17 and 18 AS-REP extraction.

use std::collections::BTreeSet;

use super::krb5asrep23::kerberos;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5AsrepAes;
use crate::{HashType, HashValue};

pub struct Krb5AsrepAesExtractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5AsrepAes>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in kerberos::messages(artifact)? {
        if message.kind != kerberos::Kind::AsRep
            || !matches!(message.etype, 17 | 18)
            || message.cipher.len() <= 12
        {
            continue;
        }
        let split = message.cipher.len() - 12;
        let checksum: [u8; 12] = message
            .cipher
            .get(split..)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ExtractError::Invalid("short Kerberos checksum".to_owned()))?;
        let etype = u8::try_from(message.etype)
            .map_err(|_| ExtractError::Invalid("invalid Kerberos etype".to_owned()))?;
        records.insert((
            etype,
            message.username,
            message.realm,
            checksum,
            message.cipher[..split].to_vec(),
        ));
    }
    Ok(records
        .into_iter()
        .map(
            |(etype, username, realm, checksum, ciphertext)| Krb5AsrepAes {
                etype,
                username,
                realm,
                checksum,
                ciphertext,
            },
        )
        .collect())
}

impl Extractor for Krb5AsrepAesExtractor {
    fn slug(&self) -> &'static str {
        Krb5AsrepAes::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match kerberos::messages(artifact) {
            Ok(messages) => {
                let etypes: Vec<i32> = messages
                    .iter()
                    .filter(|message| message.kind == kerberos::Kind::AsRep)
                    .map(|message| message.etype)
                    .collect();
                if etypes.contains(&17) {
                    Probe::yes("Kerberos AS-REP etype 17 message")
                } else if etypes.contains(&18) {
                    Probe::yes("Kerberos AS-REP etype 18 message")
                } else {
                    Probe::No
                }
            }
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos AS-REP etype 17/18 messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
