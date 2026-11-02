//! PPP MSCHAPv2 exchange extraction.

use std::collections::BTreeSet;

use super::chap::ppp;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::format;
use crate::types::Mschapv2NaiveJohn;
use crate::{HashType, HashValue};

pub struct Mschapv2NaiveExtractor;

fn values(artifact: &Artifact) -> Result<Vec<Mschapv2NaiveJohn>, ExtractError> {
    let mut records = BTreeSet::new();
    for exchange in ppp::exchanges(artifact)? {
        if exchange.challenge.len() != 16 || exchange.response.len() != 49 {
            continue;
        }
        if exchange.response[16..24] != [0; 8] {
            return Err(ExtractError::Invalid(
                "MSCHAPv2 response has a non-zero reserved field".to_owned(),
            ));
        }
        let data = format!(
            "{}:::{}:{}:{}",
            exchange.name,
            format::hex(&exchange.challenge),
            format::hex(&exchange.response[24..48]),
            format::hex(&exchange.response[..16])
        );
        records.insert(data);
    }
    Ok(records
        .into_iter()
        .map(|data| Mschapv2NaiveJohn { data })
        .collect())
}

impl Extractor for Mschapv2NaiveExtractor {
    fn slug(&self) -> &'static str {
        Mschapv2NaiveJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match ppp::exchanges(artifact) {
            Ok(exchanges)
                if exchanges
                    .iter()
                    .any(|value| value.challenge.len() == 16 && value.response.len() == 49) =>
            {
                Probe::yes("PPP MSCHAPv2 challenge-response")
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
                "no PPP MSCHAPv2 exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
