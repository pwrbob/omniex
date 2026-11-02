//! Legacy WPA PMKID extraction from packet captures.
//!
//! Legacy mode `16800` serializes the same PMKID record as the older
//! colon-separated `pmkid:ap:sta:essid` line. Handshakes have no legacy
//! representation, so only PMKID records are produced here.

use super::wpa_pmkid::{net, scan_for_pmkids};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::WpaPmkidLegacy;
use crate::{HashType, HashValue};

pub struct WpaPmkidLegacyExtractor;

fn scan(artifact: &Artifact) -> Result<Vec<WpaPmkidLegacy>, ExtractError> {
    let records = scan_for_pmkids(artifact)?;
    Ok(records
        .into_iter()
        .map(|(access_point, station, pmkid, essid)| WpaPmkidLegacy {
            pmkid,
            access_point,
            station,
            essid,
        })
        .collect())
}

impl Extractor for WpaPmkidLegacyExtractor {
    fn slug(&self) -> &'static str {
        WpaPmkidLegacy::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if !net::is_capture(artifact.primary()) {
            return Probe::No;
        }
        match scan(artifact) {
            Ok(records) if !records.is_empty() => Probe::yes("WPA PMKID records"),
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported("no WPA PMKID records".to_owned()));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
