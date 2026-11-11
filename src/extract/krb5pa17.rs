//! Kerberos 5 etype 17 AS-REQ pre-authentication extraction.

use std::collections::BTreeSet;

use super::krb5pa23::asreq;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5Pa17;
use crate::{HashType, HashValue};

pub struct Krb5Pa17Extractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5Pa17>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in asreq::messages(artifact)? {
        if message.etype != 17 || message.cipher.len() <= 12 {
            continue;
        }
        records.insert((message.username, message.realm, message.cipher));
    }
    Ok(records
        .into_iter()
        .map(|(username, realm, ciphertext)| Krb5Pa17 {
            username,
            realm,
            salt: String::new(),
            ciphertext,
        })
        .collect())
}

impl Extractor for Krb5Pa17Extractor {
    fn slug(&self) -> &'static str {
        Krb5Pa17::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        asreq::probe_artifact(artifact, 17)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos AS-REQ etype 17 pre-authentication messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
