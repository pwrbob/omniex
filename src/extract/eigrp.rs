//! EIGRP MD5 and HMAC-SHA-256 authentication extraction.

use std::collections::BTreeSet;

use super::ospf_md5::packet;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Eigrp;
use crate::{HashType, HashValue};

fn extra_salt(data: &[u8], offset: usize) -> (bool, String) {
    let mut offset = offset;
    let mut have_extra = false;
    let mut extra = String::new();
    let mut parameters: Option<Vec<u8>> = None;
    let mut version: Option<Vec<u8>> = None;
    let mut peer: Option<Vec<u8>> = None;
    let mut internal_routes = Vec::new();

    while offset + 4 <= data.len() {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
        if length < 4 || offset + length > data.len() {
            break;
        }
        let value = &data[offset..offset + length];
        match kind {
            1 => {
                parameters = Some(value[..value.len() - 2].to_vec());
                offset += length;
            }
            4 => {
                version = Some(value.to_vec());
                offset += length;
            }
            0x00f5 => {
                let mut value = data[offset..offset + 6].to_vec();
                value.push(0);
                peer = Some(value);
                have_extra = true;
                extra = crate::format::hex(parameters.as_deref().unwrap_or(&[]));
                offset += length;
            }
            3 => {
                let mut value = Vec::new();
                value.extend_from_slice(parameters.as_deref().unwrap_or(&[]));
                value.extend_from_slice(version.as_deref().unwrap_or(&[]));
                value.extend_from_slice(peer.as_deref().unwrap_or(&[]));
                extra = crate::format::hex(&value);
                have_extra = true;
                offset += length;
            }
            0x00f2 => {
                let mut value = data[offset..offset + 22].to_vec();
                value.push(0);
                extra = crate::format::hex(&value);
                have_extra = true;
                offset += length;
            }
            0x0602 => {
                internal_routes.extend_from_slice(value);
                have_extra = true;
                offset += length;
            }
            _ => break,
        }
    }

    if !internal_routes.is_empty() {
        if internal_routes.len() >= 20 {
            internal_routes.truncate(internal_routes.len() - 20);
        }
        extra.push_str(&crate::format::hex(&internal_routes));
    }

    if have_extra {
        (true, extra)
    } else {
        (false, "x".to_owned())
    }
}

fn zero_occurrences(data: &mut [u8], needle: &[u8]) {
    if needle.is_empty() || needle.len() > data.len() {
        return;
    }
    for start in 0..=data.len() - needle.len() {
        if &data[start..start + needle.len()] == needle {
            data[start..start + needle.len()].fill(0);
        }
    }
}

fn record(ip: &packet::Ip<'_>) -> Option<Eigrp> {
    let data = ip.payload;
    if data.len() < 40 || data[0] != 2 {
        return None;
    }
    let opcode = data[1];
    let flags = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if opcode == 1 && flags == 1 {
        return None;
    }
    if u16::from_be_bytes([data[20], data[21]]) != 2 {
        return None;
    }
    let algorithm = u16::from_be_bytes([data[24], data[25]]);
    if algorithm != 2 && algorithm != 3 {
        return None;
    }
    let hash_length = usize::from(u16::from_be_bytes([data[26], data[27]]));
    if hash_length < 16 || data.len() < 44 + hash_length {
        return None;
    }
    let hash = &data[44..44 + hash_length];

    let mut salt = Vec::new();
    if algorithm == 2 {
        salt.extend_from_slice(&data[..2]);
        salt.extend_from_slice(&[0u8; 4]);
        salt.extend_from_slice(&data[6..44]);
    } else {
        salt.extend_from_slice(&data[..2]);
        salt.extend_from_slice(&[0u8; 4]);
        salt.extend_from_slice(&data[6..]);
        zero_occurrences(&mut salt, hash);
    }

    let (have_extra, extra) = extra_salt(data, 60);
    let destination = packet::ip_string(ip);
    let fields = format!(
        "{algorithm}${}${}${}$1${destination}${}",
        crate::format::hex(&salt),
        u8::from(have_extra),
        extra,
        crate::format::hex(hash)
    );
    Some(Eigrp { fields })
}

fn scan_records(artifact: &Artifact) -> Result<Vec<Eigrp>, ExtractError> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    packet::scan(artifact.primary(), |ip| {
        if ip.protocol != packet::PROTOCOL_EIGRP {
            return;
        }
        let Some(value) = record(&ip) else {
            return;
        };
        if seen.insert(value.fields.clone()) {
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
        Ok(values) if !values.is_empty() => Probe::yes("EIGRP authentication records"),
        Ok(_) => Probe::No,
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for EIGRP authentication hashes.
pub struct EigrpExtractor;

impl Extractor for EigrpExtractor {
    fn slug(&self) -> &'static str {
        Eigrp::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no EIGRP authentication records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
