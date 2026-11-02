//! IKEv1 aggressive-mode pre-shared-key extraction (SHA1).

use std::collections::BTreeSet;

use super::ike_psk_md5::ike;
use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::IkePskSha1;
use omniex::{HashType, HashValue, Render};

fn scan_records(artifact: &Artifact) -> Result<Vec<IkePskSha1>, ExtractError> {
    let (exchanges, _) = ike::scan(artifact)?;
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    for exchange in exchanges {
        if exchange.hash_r.len() != 20 {
            continue;
        }
        let Ok(digest) = exchange.hash_r.as_slice().try_into() else {
            continue;
        };
        let value = IkePskSha1 {
            message_0: exchange.g_xr,
            message_1: exchange.g_xi,
            message_2: exchange.cky_r.to_vec(),
            message_3: exchange.cky_i.to_vec(),
            message_4: exchange.sai_b,
            message_5: exchange.idir_b,
            nonce_0: exchange.ni_b,
            nonce_1: exchange.nr_b,
            digest,
        };
        if seen.insert(
            value
                .render(&omniex::RenderOptions::default())
                .unwrap_or_default(),
        ) {
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
            if exchanges.iter().any(|exchange| exchange.hash_r.len() == 20) {
                Probe::yes("IKEv1 aggressive-mode SHA1 exchange")
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

/// Extractor for IKEv1 aggressive-mode SHA1 hashes.
pub struct IkePskSha1Extractor;

impl Extractor for IkePskSha1Extractor {
    fn slug(&self) -> &'static str {
        IkePskSha1::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no IKEv1 aggressive-mode SHA1 exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
