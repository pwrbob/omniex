//! HSRP, HSRPv2, VRRP, and GLBP MD5 authentication extraction.

use std::collections::BTreeSet;

use super::ospf_md5::packet;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Hsrp;
use crate::{HashType, HashValue};

const HSRP_PORT: u16 = 1985;

fn version_one(data: &[u8]) -> Option<Hsrp> {
    if data.len() < 50 || data[0] > 1 || data[20] != 4 {
        return None;
    }
    let length = usize::from(data[21]);
    if length < 16 {
        return None;
    }
    let end = 20usize.checked_add(2)?.checked_add(length)?;
    if end > data.len() {
        return None;
    }
    let start = end - 16;
    let digest: [u8; 16] = data[start..end].try_into().ok()?;
    let mut salt = data[..start].to_vec();
    salt.resize(start + 16, 0);
    Some(Hsrp {
        data: crate::format::hex(&salt),
        digest,
    })
}

fn version_two(data: &[u8]) -> Option<Hsrp> {
    let mut offset = 0;
    let mut salt = Vec::new();
    let mut digest = None;
    let mut saw_group = false;
    while offset + 2 <= data.len() {
        let kind = data[offset];
        let length = usize::from(data[offset + 1]);
        let total = length.checked_add(2)?;
        if total < 2 || offset + total > data.len() {
            break;
        }
        match kind {
            1 => {
                salt.extend_from_slice(&data[offset..offset + total]);
                saw_group = true;
            }
            4 => {
                if length < 16 {
                    return None;
                }
                let value = &data[offset..offset + total];
                let start = value.len() - 16;
                digest = Some(<[u8; 16]>::try_from(&value[start..]).ok()?);
                salt.extend_from_slice(&value[..start]);
                salt.extend_from_slice(&[0u8; 16]);
            }
            _ => break,
        }
        offset += total;
    }
    if !saw_group {
        return None;
    }
    Some(Hsrp {
        data: crate::format::hex(&salt),
        digest: digest?,
    })
}

fn record(data: &[u8]) -> Option<Hsrp> {
    version_one(data).or_else(|| version_two(data))
}

fn scan_records(artifact: &Artifact) -> Result<Vec<Hsrp>, ExtractError> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    packet::scan(artifact.primary(), |ip| {
        if ip.protocol != packet::PROTOCOL_UDP {
            return;
        }
        let Some((source, destination, data)) = packet::udp(ip.payload) else {
            return;
        };
        if source != HSRP_PORT && destination != HSRP_PORT {
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
        Ok(values) if !values.is_empty() => Probe::yes("HSRP MD5 authentication records"),
        Ok(_) => Probe::No,
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for HSRP MD5 authentication hashes.
pub struct HsrpExtractor;

impl Extractor for HsrpExtractor {
    fn slug(&self) -> &'static str {
        Hsrp::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no HSRP MD5 authentication records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
