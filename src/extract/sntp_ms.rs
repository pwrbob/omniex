//! Microsoft SNTP (Timeroast) authentication extraction.

use std::collections::BTreeSet;

use super::ospf_md5::packet;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::SntpMs;
use crate::{HashType, HashValue};

const NTP_PORT: u16 = 123;
const NTP_HEADER: usize = 48;
const TIMEROAST_PACKET: usize = 68;

fn record(data: &[u8]) -> Option<SntpMs> {
    if data.len() != TIMEROAST_PACKET {
        return None;
    }
    let mode = data[0] & 0x07;
    let version = (data[0] >> 3) & 0x07;
    if mode != 4 || !(3..=4).contains(&version) {
        return None;
    }
    let digest: [u8; 16] = data[TIMEROAST_PACKET - 16..].try_into().ok()?;
    Some(SntpMs {
        digest,
        data: data[..NTP_HEADER].to_vec(),
    })
}

fn scan_records(artifact: &Artifact) -> Result<Vec<SntpMs>, ExtractError> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    packet::scan(artifact.primary(), |ip| {
        if ip.protocol != packet::PROTOCOL_UDP {
            return;
        }
        let Some((source, destination, data)) = packet::udp(ip.payload) else {
            return;
        };
        if source != NTP_PORT && destination != NTP_PORT {
            return;
        }
        let Some(value) = record(data) else {
            return;
        };
        if seen.insert((value.data.clone(), value.digest)) {
            values.push(value);
        }
    })?;
    Ok(values)
}

fn probe_records(artifact: &Artifact) -> Probe {
    if !super::wpa_pmkid::net::is_capture(artifact.primary()) {
        return Probe::No;
    }
    match scan_records(artifact) {
        Ok(values) if !values.is_empty() => Probe::yes("MS SNTP authentication records"),
        Ok(_) => Probe::No,
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for Microsoft SNTP authentication hashes.
pub struct SntpMsExtractor;

impl Extractor for SntpMsExtractor {
    fn slug(&self) -> &'static str {
        SntpMs::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no MS SNTP authentication records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
