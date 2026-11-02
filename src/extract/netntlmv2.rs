//! NTLMSSP NetNTLMv2 exchange extraction.

use std::collections::BTreeSet;

use super::netntlmv1::ntlm;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::NetNtlmV2;
use crate::{HashType, HashValue};

pub struct NetNtlmV2Extractor;

fn values(artifact: &Artifact) -> Result<Vec<NetNtlmV2>, ExtractError> {
    let mut records = BTreeSet::new();
    for exchange in ntlm::exchanges(artifact)? {
        if let ntlm::Exchange::V2(value) = exchange {
            records.insert((
                value.username,
                value.domain,
                value.challenge,
                value.nt_proof,
                value.blob,
            ));
        }
    }
    Ok(records
        .into_iter()
        .map(|(username, domain, challenge, nt_proof, blob)| NetNtlmV2 {
            username,
            domain,
            challenge,
            nt_proof,
            blob,
        })
        .collect())
}

impl Extractor for NetNtlmV2Extractor {
    fn slug(&self) -> &'static str {
        NetNtlmV2::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match ntlm::exchanges(artifact) {
            Ok(exchanges)
                if exchanges
                    .iter()
                    .any(|value| matches!(value, ntlm::Exchange::V2(_))) =>
            {
                Probe::yes("NTLMSSP NetNTLMv2 challenge-response")
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no NTLMSSP NetNTLMv2 exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
