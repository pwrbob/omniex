//! TCP MD5 signature extraction from packet captures.

use std::collections::BTreeSet;

use super::ospf_md5::packet;
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::TcpMd5;
use crate::{HashType, HashValue};

fn tcp_option_md5(header: &[u8]) -> Option<[u8; 16]> {
    let mut offset = 20;
    while offset < header.len() {
        let kind = header[offset];
        if kind == 0 {
            return None;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let length = usize::from(*header.get(offset + 1)?);
        if length < 2 || offset + length > header.len() {
            return None;
        }
        if kind == 19 {
            if length != 18 {
                return None;
            }
            return header[offset + 2..offset + 18].try_into().ok();
        }
        offset += length;
    }
    None
}

fn scan_records(artifact: &Artifact) -> Result<Vec<TcpMd5>, ExtractError> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    packet::scan(artifact.primary(), |ip| {
        if ip.protocol != packet::PROTOCOL_TCP || ip.version != 4 {
            return;
        }
        let Some(tcp) = packet::tcp(ip.payload) else {
            return;
        };
        let Some(digest) = tcp_option_md5(tcp.header) else {
            return;
        };
        let total = tcp.header.len() + tcp.payload.len();
        let Ok(total) = u16::try_from(total) else {
            return;
        };
        let mut salt = Vec::with_capacity(32 + tcp.payload.len());
        salt.extend_from_slice(&ip.source[..4]);
        salt.extend_from_slice(&ip.destination[..4]);
        salt.push(0);
        salt.push(ip.protocol);
        salt.extend_from_slice(&total.to_be_bytes());
        salt.extend_from_slice(&tcp.header[..16]);
        salt.extend_from_slice(&[0u8; 4]);
        salt.extend_from_slice(tcp.payload);
        let packet = crate::format::hex(&salt);
        if seen.insert((packet.clone(), digest)) {
            values.push(TcpMd5 { packet, digest });
        }
    })?;
    Ok(values)
}

fn probe_records(artifact: &Artifact) -> Probe {
    if !super::wpa_pmkid::net::is_capture(artifact.primary()) {
        return Probe::No;
    }
    match scan_records(artifact) {
        Ok(values) if !values.is_empty() => Probe::yes("TCP MD5 signature records"),
        Ok(_) => Probe::No,
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for TCP MD5 signatures.
pub struct TcpMd5Extractor;

impl Extractor for TcpMd5Extractor {
    fn slug(&self) -> &'static str {
        TcpMd5::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no TCP MD5 signature records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
