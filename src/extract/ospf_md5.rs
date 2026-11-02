//! OSPFv2 and RIPv2 MD5 authentication extraction from packet captures.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::OspfMd5;
use crate::{HashType, HashValue};

pub(crate) mod packet {
    //! Minimal link, IP, UDP, and TCP decoding shared by the routing extractors.

    use super::super::wpa_pmkid::net;
    use super::super::{ExtractError, ReadAt};

    const LINKTYPE_ETHERNET: u32 = 1;
    const LINKTYPE_RAW: u32 = 101;
    const LINKTYPE_RAW_ALT: u32 = 12;
    const LINKTYPE_IPV4: u32 = 228;
    const LINKTYPE_IPV6: u32 = 229;
    const LINKTYPE_LINUX_SLL: u32 = 113;
    const LINKTYPE_LINUX_SLL2: u32 = 276;

    pub(crate) const PROTOCOL_TCP: u8 = 6;
    pub(crate) const PROTOCOL_UDP: u8 = 17;
    pub(crate) const PROTOCOL_OSPF: u8 = 89;
    pub(crate) const PROTOCOL_EIGRP: u8 = 88;

    /// One decoded IP packet.
    pub(crate) struct Ip<'a> {
        /// IP version.
        pub(crate) version: u8,
        /// Source address, zero padded for IPv4.
        pub(crate) source: [u8; 16],
        /// Destination address, zero padded for IPv4.
        pub(crate) destination: [u8; 16],
        /// Upper-layer protocol number.
        pub(crate) protocol: u8,
        /// Upper-layer payload.
        pub(crate) payload: &'a [u8],
    }

    /// One decoded TCP segment.
    pub(crate) struct Tcp<'a> {
        /// TCP header including options.
        pub(crate) header: &'a [u8],
        /// TCP payload.
        pub(crate) payload: &'a [u8],
    }

    fn link_payload(link_type: u32, frame: &[u8]) -> Option<(u16, &[u8])> {
        match link_type {
            LINKTYPE_ETHERNET => {
                if frame.len() < 14 {
                    return None;
                }
                let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                let mut offset = 14;
                while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                    let inner = frame.get(offset..offset + 4)?;
                    ethertype = u16::from_be_bytes([inner[2], inner[3]]);
                    offset += 4;
                }
                Some((ethertype, &frame[offset..]))
            }
            LINKTYPE_RAW | LINKTYPE_RAW_ALT => {
                let version = frame.first()? >> 4;
                let ethertype = if version == 6 { 0x86dd } else { 0x0800 };
                Some((ethertype, frame))
            }
            LINKTYPE_IPV4 => Some((0x0800, frame)),
            LINKTYPE_IPV6 => Some((0x86dd, frame)),
            LINKTYPE_LINUX_SLL => {
                let header = frame.get(..16)?;
                Some((u16::from_be_bytes([header[14], header[15]]), &frame[16..]))
            }
            LINKTYPE_LINUX_SLL2 => {
                let header = frame.get(..20)?;
                Some((u16::from_be_bytes([header[0], header[1]]), &frame[20..]))
            }
            _ => None,
        }
    }

    fn ip_packet(link_type: u32, frame: &[u8]) -> Option<Ip<'_>> {
        let (ethertype, data) = link_payload(link_type, frame)?;
        match ethertype {
            0x0800 => {
                if data.len() < 20 || data[0] >> 4 != 4 {
                    return None;
                }
                let header = usize::from(data[0] & 0x0f) * 4;
                if header < 20 || data.len() < header {
                    return None;
                }
                let total = usize::from(u16::from_be_bytes([data[2], data[3]])).min(data.len());
                if total < header {
                    return None;
                }
                let fragment = u16::from_be_bytes([data[6], data[7]]);
                if fragment & 0x3fff != 0 {
                    return None;
                }
                let mut source = [0u8; 16];
                source[..4].copy_from_slice(&data[12..16]);
                let mut destination = [0u8; 16];
                destination[..4].copy_from_slice(&data[16..20]);
                Some(Ip {
                    version: 4,
                    source,
                    destination,
                    protocol: data[9],
                    payload: &data[header..total],
                })
            }
            0x86dd => {
                if data.len() < 40 || data[0] >> 4 != 6 {
                    return None;
                }
                let total = 40 + usize::from(u16::from_be_bytes([data[4], data[5]]));
                let end = total.min(data.len());
                let mut next = data[6];
                let mut rest = data.get(40..end)?;
                while matches!(next, 0 | 43 | 60) {
                    let header = (usize::from(*rest.get(1)?) + 1) * 8;
                    next = *rest.first()?;
                    rest = rest.get(header..)?;
                }
                if next == 44 {
                    return None;
                }
                let mut source = [0u8; 16];
                source.copy_from_slice(&data[8..24]);
                let mut destination = [0u8; 16];
                destination.copy_from_slice(&data[24..40]);
                Some(Ip {
                    version: 6,
                    source,
                    destination,
                    protocol: next,
                    payload: rest,
                })
            }
            _ => None,
        }
    }

    /// Visits every decoded IP packet in a capture.
    pub(crate) fn scan<F>(source: &dyn ReadAt, mut visit: F) -> Result<(), ExtractError>
    where
        F: FnMut(Ip<'_>),
    {
        net::scan(source, |link_type, frame| {
            if let Some(packet) = ip_packet(link_type, frame) {
                visit(packet);
            }
        })
    }

    /// Decodes a UDP datagram into source port, destination port, and payload.
    pub(crate) fn udp(data: &[u8]) -> Option<(u16, u16, &[u8])> {
        if data.len() < 8 {
            return None;
        }
        let source = u16::from_be_bytes([data[0], data[1]]);
        let destination = u16::from_be_bytes([data[2], data[3]]);
        let length = usize::from(u16::from_be_bytes([data[4], data[5]]));
        if length < 8 || length > data.len() {
            return None;
        }
        Some((source, destination, &data[8..length]))
    }

    /// Decodes a TCP segment into header and payload.
    pub(crate) fn tcp(data: &[u8]) -> Option<Tcp<'_>> {
        if data.len() < 20 {
            return None;
        }
        let header = usize::from(data[12] >> 4) * 4;
        if header < 20 || header > data.len() {
            return None;
        }
        Some(Tcp {
            header: &data[..header],
            payload: &data[header..],
        })
    }

    /// Formats an IP address for the EIGRP serialization.
    pub(crate) fn ip_string(packet: &Ip<'_>) -> String {
        if packet.version == 4 {
            format!(
                "{}.{}.{}.{}",
                packet.source[0], packet.source[1], packet.source[2], packet.source[3]
            )
        } else {
            std::net::Ipv6Addr::from(packet.source).to_string()
        }
    }
}

fn scan_records(artifact: &Artifact) -> Result<Vec<OspfMd5>, ExtractError> {
    let mut seen = BTreeSet::new();
    let mut values = Vec::new();
    packet::scan(artifact.primary(), |ip| {
        if ip.protocol == packet::PROTOCOL_OSPF {
            if let Some(value) = ospf(ip.payload) {
                if seen.insert((value.packet.clone(), value.digest)) {
                    values.push(value);
                }
            }
        } else if ip.protocol == packet::PROTOCOL_UDP {
            if let Some((source, destination, data)) = packet::udp(ip.payload) {
                if source != 520 && destination != 520 {
                    return;
                }
                if let Some(value) = rip(data) {
                    if seen.insert((value.packet.clone(), value.digest)) {
                        values.push(value);
                    }
                }
            }
        }
    })?;
    Ok(values)
}

fn ospf(data: &[u8]) -> Option<OspfMd5> {
    if data.len() < 24 || data[0] != 2 || data[14] != 0 || data[15] != 2 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if length < 24 || data.len() < length + 16 {
        return None;
    }
    let digest: [u8; 16] = data[length..length + 16].try_into().ok()?;
    Some(OspfMd5 {
        packet: data[..length].to_vec(),
        digest,
    })
}

fn rip(data: &[u8]) -> Option<OspfMd5> {
    if data.len() < 24
        || data[1] != 2
        || data[4] != 0xff
        || data[5] != 0xff
        || data[6] != 0
        || data[7] != 3
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([data[8], data[9]]));
    let offset = length.checked_add(4)?;
    if length < 24 || offset.checked_add(16)? > data.len() {
        return None;
    }
    if data[length] != 0xff
        || data[length + 1] != 0xff
        || data[length + 2] != 0
        || data[length + 3] != 1
    {
        return None;
    }
    let digest: [u8; 16] = data[offset..offset + 16].try_into().ok()?;
    Some(OspfMd5 {
        packet: data[..offset].to_vec(),
        digest,
    })
}

fn probe_records(artifact: &Artifact) -> Probe {
    if !super::wpa_pmkid::net::is_capture(artifact.primary()) {
        return Probe::No;
    }
    match scan_records(artifact) {
        Ok(values) if !values.is_empty() => Probe::yes("OSPFv2/RIPv2 MD5 authentication records"),
        Ok(_) => Probe::No,
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

/// Extractor for OSPFv2 and RIPv2 MD5 authentication hashes.
pub struct OspfMd5Extractor;

impl Extractor for OspfMd5Extractor {
    fn slug(&self) -> &'static str {
        OspfMd5::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no OSPFv2/RIPv2 MD5 authentication records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
