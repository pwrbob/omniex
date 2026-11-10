//! IKEv1 aggressive-mode extraction in the John `$ike$` serialization.

use std::collections::BTreeSet;

use super::ike_psk_md5::ike;
use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::IkeJohn;
use omniex::{HashType, HashValue};

fn scan_records(artifact: &Artifact) -> Result<Vec<IkeJohn>, ExtractError> {
    let (exchanges, _) = ike::scan(artifact)?;
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for exchange in exchanges {
        if exchange.hash_r.len() != 16 && exchange.hash_r.len() != 20 {
            continue;
        }
        let value = IkeJohn {
            fields: exchange.john_fields(),
        };
        if seen.insert(value.fields.clone()) {
            values.push(value);
        }
    }
    Ok(values)
}

fn probe_records(artifact: &Artifact) -> Probe {
    if !ike::is_capture(artifact.primary()) {
        return Probe::No;
    }
    match ike::scan(artifact) {
        Ok((exchanges, saw_ike)) => {
            if exchanges
                .iter()
                .any(|exchange| exchange.hash_r.len() == 16 || exchange.hash_r.len() == 20)
            {
                Probe::maybe("IKEv1 aggressive-mode exchange; use --type ike-payload")
            } else if exchanges.is_empty() && saw_ike {
                Probe::maybe("IKEv1 aggressive-mode packets without a complete exchange")
            } else {
                Probe::No
            }
        }
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for IKE hashes in the John serialization.
pub struct IkeJohnExtractor;

impl Extractor for IkeJohnExtractor {
    fn slug(&self) -> &'static str {
        IkeJohn::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no IKEv1 aggressive-mode exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
