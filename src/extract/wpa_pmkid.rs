//! WPA/WPA2 EAPOL and PMKID extraction from packet captures.
//!
//! The capture reader and link-layer helpers live in [`net`] so the Kerberos
//! extractors decode the same captures without duplicating the container code.

use std::collections::{BTreeMap, BTreeSet};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::WpaPmkid;
use crate::{HashType, HashValue};

pub(crate) mod net {
    //! Bounded streaming packet-capture reader shared by network extractors.

    use crate::extract::{ExtractError, ReadAt};

    pub(crate) const LINKTYPE_ETHERNET: u32 = 1;
    pub(crate) const LINKTYPE_IEEE802_11: u32 = 105;
    pub(crate) const LINKTYPE_RADIOTAP: u32 = 127;
    const LINKTYPE_RAW: u32 = 101;
    const LINKTYPE_RAW_ALT: u32 = 12;
    const LINKTYPE_IPV4: u32 = 228;
    const LINKTYPE_IPV6: u32 = 229;
    const LINKTYPE_LINUX_SLL: u32 = 113;
    const LINKTYPE_LINUX_SLL2: u32 = 276;

    const MAX_PACKET: u64 = 262_144;
    const MAX_BLOCK: u64 = 64 * 1024 * 1024;

    const PCAP_MAGIC_USEC_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
    const PCAP_MAGIC_USEC_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
    const PCAP_MAGIC_NSEC_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
    const PCAP_MAGIC_NSEC_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
    const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

    fn truncated() -> ExtractError {
        ExtractError::Invalid("truncated packet capture".to_owned())
    }

    fn not_capture() -> ExtractError {
        ExtractError::Unsupported("not a packet capture".to_owned())
    }

    /// Returns whether the artifact starts with a supported capture signature.
    pub(crate) fn is_capture(source: &dyn ReadAt) -> bool {
        let mut magic = [0u8; 4];
        if source.read_exact_at(0, &mut magic).is_err() {
            return false;
        }
        magic == PCAP_MAGIC_USEC_LE
            || magic == PCAP_MAGIC_USEC_BE
            || magic == PCAP_MAGIC_NSEC_LE
            || magic == PCAP_MAGIC_NSEC_BE
            || magic == PCAPNG_MAGIC
    }

    fn u16_at(source: &dyn ReadAt, offset: u64, big_endian: bool) -> Result<u16, ExtractError> {
        let mut buffer = [0u8; 2];
        source
            .read_exact_at(offset, &mut buffer)
            .map_err(|_| truncated())?;
        Ok(if big_endian {
            u16::from_be_bytes(buffer)
        } else {
            u16::from_le_bytes(buffer)
        })
    }

    fn u32_at(source: &dyn ReadAt, offset: u64, big_endian: bool) -> Result<u32, ExtractError> {
        let mut buffer = [0u8; 4];
        source
            .read_exact_at(offset, &mut buffer)
            .map_err(|_| truncated())?;
        Ok(if big_endian {
            u32::from_be_bytes(buffer)
        } else {
            u32::from_le_bytes(buffer)
        })
    }

    /// Visits every captured frame with its link type.
    pub(crate) fn scan<F>(source: &dyn ReadAt, mut visit: F) -> Result<(), ExtractError>
    where
        F: FnMut(u32, &[u8]),
    {
        let len = source.len();
        let mut magic = [0u8; 4];
        source
            .read_exact_at(0, &mut magic)
            .map_err(|_| not_capture())?;
        match magic {
            PCAP_MAGIC_USEC_LE => scan_classic(source, len, false, &mut visit),
            PCAP_MAGIC_USEC_BE => scan_classic(source, len, true, &mut visit),
            PCAP_MAGIC_NSEC_LE => scan_classic(source, len, false, &mut visit),
            PCAP_MAGIC_NSEC_BE => scan_classic(source, len, true, &mut visit),
            PCAPNG_MAGIC => scan_ng(source, len, &mut visit),
            _ => Err(not_capture()),
        }
    }

    fn scan_classic<F>(
        source: &dyn ReadAt,
        len: u64,
        big_endian: bool,
        visit: &mut F,
    ) -> Result<(), ExtractError>
    where
        F: FnMut(u32, &[u8]),
    {
        if len < 24 {
            return Err(truncated());
        }
        let link_type = u32_at(source, 20, big_endian)?;
        let mut offset = 24u64;
        let mut buffer = Vec::new();
        let mut saw_packet = false;
        while offset < len {
            if offset + 16 > len {
                if len - offset > 1 {
                    return Err(truncated());
                }
                break;
            }
            let captured = u64::from(u32_at(source, offset + 8, big_endian)?);
            offset += 16;
            if offset + captured > len {
                if !saw_packet && len - offset > 1 {
                    return Err(truncated());
                }
                break;
            }
            if captured <= MAX_PACKET {
                buffer.resize(captured as usize, 0);
                source
                    .read_exact_at(offset, &mut buffer)
                    .map_err(|_| truncated())?;
                visit(link_type, &buffer);
                saw_packet = true;
            }
            offset += captured;
        }
        Ok(())
    }

    fn scan_ng<F>(source: &dyn ReadAt, len: u64, visit: &mut F) -> Result<(), ExtractError>
    where
        F: FnMut(u32, &[u8]),
    {
        let mut byte_order = [0u8; 4];
        source
            .read_exact_at(8, &mut byte_order)
            .map_err(|_| truncated())?;
        let big_endian = match byte_order {
            [0x1a, 0x2b, 0x3c, 0x4d] => true,
            [0x4d, 0x3c, 0x2b, 0x1a] => false,
            _ => {
                return Err(ExtractError::Invalid(
                    "invalid pcapng byte-order magic".to_owned(),
                ));
            }
        };
        let mut interfaces: Vec<u32> = Vec::new();
        let mut offset = 0u64;
        let mut buffer = Vec::new();
        while offset < len {
            if offset + 12 > len {
                return Err(truncated());
            }
            let block_type = u32_at(source, offset, big_endian)?;
            let total = u64::from(u32_at(source, offset + 4, big_endian)?);
            if !(12..=MAX_BLOCK).contains(&total) || offset + total > len {
                return Err(truncated());
            }
            let body = total - 12;
            match block_type {
                1 => {
                    interfaces.push(u32::from(u16_at(source, offset + 8, big_endian)?));
                }
                6 if body >= 20 => {
                    let interface = u32_at(source, offset + 8, big_endian)? as usize;
                    let captured = u64::from(u32_at(source, offset + 20, big_endian)?);
                    if let Some(link_type) = interfaces.get(interface) {
                        if captured <= MAX_PACKET && 20 + captured <= body {
                            buffer.resize(captured as usize, 0);
                            source
                                .read_exact_at(offset + 28, &mut buffer)
                                .map_err(|_| truncated())?;
                            visit(*link_type, &buffer);
                        }
                    }
                }
                3 if body >= 4 => {
                    let original = u64::from(u32_at(source, offset + 8, big_endian)?);
                    let length = original.min(body - 4).min(MAX_PACKET);
                    if let Some(link_type) = interfaces.first().copied() {
                        if length > 0 {
                            buffer.resize(length as usize, 0);
                            source
                                .read_exact_at(offset + 12, &mut buffer)
                                .map_err(|_| truncated())?;
                            visit(link_type, &buffer);
                        }
                    }
                }
                2 if body >= 20 => {
                    let interface = u16_at(source, offset + 8, big_endian)? as usize;
                    let captured = u64::from(u32_at(source, offset + 20, big_endian)?);
                    if let Some(link_type) = interfaces.get(interface) {
                        if captured <= MAX_PACKET && 20 + captured <= body {
                            buffer.resize(captured as usize, 0);
                            source
                                .read_exact_at(offset + 28, &mut buffer)
                                .map_err(|_| truncated())?;
                            visit(*link_type, &buffer);
                        }
                    }
                }
                _ => {}
            }
            offset += total;
        }
        Ok(())
    }

    /// Strips a radiotap header when the link type carries one.
    pub(crate) fn dot11(link_type: u32, frame: &[u8]) -> Option<&[u8]> {
        match link_type {
            LINKTYPE_IEEE802_11 => Some(frame),
            LINKTYPE_RADIOTAP => {
                let length = usize::from(u16::from_le_bytes(frame.get(2..4)?.try_into().ok()?));
                frame.get(length..)
            }
            _ => None,
        }
    }

    /// Returns the 802.11 MAC header length, including QoS and address fields.
    pub(crate) fn dot11_header_len(frame: &[u8]) -> Option<usize> {
        let control = u16::from_le_bytes(frame.get(..2)?.try_into().ok()?);
        if control & 0x0003 != 0 {
            return None;
        }
        let kind = (control >> 2) & 0x3;
        let subtype = (control >> 4) & 0xf;
        let flags = (control >> 8) as u8;
        let mut length = 24;
        if flags & 0x01 != 0 && flags & 0x02 != 0 {
            length += 6;
        }
        if kind == 2 && subtype >= 8 {
            length += 2;
            if flags & 0x80 != 0 {
                length += 4;
            }
        }
        (frame.len() >= length).then_some(length)
    }

    fn ethertype_payload(link_type: u32, frame: &[u8]) -> Option<(u16, &[u8])> {
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
            LINKTYPE_IEEE802_11 | LINKTYPE_RADIOTAP => {
                let frame = dot11(link_type, frame)?;
                let control = u16::from_le_bytes(frame.get(..2)?.try_into().ok()?);
                if (control >> 2) & 0x3 != 2 {
                    return None;
                }
                let header = dot11_header_len(frame)?;
                let body = frame.get(header..)?;
                let snaplen = body.strip_prefix(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00])?;
                let ethertype = u16::from_be_bytes([*snaplen.first()?, *snaplen.get(1)?]);
                Some((ethertype, snaplen.get(2..)?))
            }
            LINKTYPE_LINUX_SLL => {
                let header = frame.get(..16)?;
                Some((u16::from_be_bytes([header[14], header[15]]), &frame[16..]))
            }
            LINKTYPE_LINUX_SLL2 => {
                let header = frame.get(..20)?;
                Some((u16::from_be_bytes([header[0], header[1]]), &frame[20..]))
            }
            LINKTYPE_RAW | LINKTYPE_RAW_ALT => {
                let version = frame.first()? >> 4;
                let ethertype = if version == 6 { 0x86dd } else { 0x0800 };
                Some((ethertype, frame))
            }
            LINKTYPE_IPV4 => Some((0x0800, frame)),
            LINKTYPE_IPV6 => Some((0x86dd, frame)),
            _ => None,
        }
    }

    fn ip_payload(ethertype: u16, data: &[u8]) -> Option<(u8, &[u8])> {
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
                Some((data[9], &data[header..total]))
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
                Some((next, rest))
            }
            _ => None,
        }
    }

    fn udp(data: &[u8]) -> Option<(u16, u16, &[u8])> {
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

    fn tcp(data: &[u8]) -> Option<(u16, u16, &[u8])> {
        if data.len() < 20 {
            return None;
        }
        let source = u16::from_be_bytes([data[0], data[1]]);
        let destination = u16::from_be_bytes([data[2], data[3]]);
        let header = usize::from(data[12] >> 4) * 4;
        if header < 20 || header > data.len() {
            return None;
        }
        let payload = &data[header..];
        if payload.len() >= 4 {
            let length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if length as usize == payload.len() - 4 {
                return Some((source, destination, &payload[4..]));
            }
        }
        Some((source, destination, payload))
    }

    /// Returns the TCP source and destination ports with the payload.
    pub(crate) fn tcp_payload(link_type: u32, frame: &[u8]) -> Option<(u16, u16, &[u8])> {
        let (ethertype, payload) = ethertype_payload(link_type, frame)?;
        let (protocol, data) = ip_payload(ethertype, payload)?;
        if protocol != 6 {
            return None;
        }
        tcp(data)
    }

    /// Returns the payload of a Kerberos (TCP/UDP port 88) packet.
    pub(crate) fn kerberos_payload(link_type: u32, frame: &[u8]) -> Option<&[u8]> {
        let (ethertype, payload) = ethertype_payload(link_type, frame)?;
        let (protocol, data) = ip_payload(ethertype, payload)?;
        let (source, destination, body) = match protocol {
            17 => udp(data)?,
            6 => tcp(data)?,
            _ => return None,
        };
        if source == 88 || destination == 88 {
            Some(body)
        } else {
            None
        }
    }
}

pub(crate) type PmkidRecord = ([u8; 6], [u8; 6], [u8; 16], Vec<u8>);
type EapolRecord = ([u8; 6], [u8; 6], [u8; 16], [u8; 32], Vec<u8>, u8);

const KIND_PMKID: &str = "01";
const KIND_EAPOL: &str = "02";

#[derive(Default)]
struct Session {
    pmkids: Vec<[u8; 16]>,
    m1: Vec<([u8; 8], [u8; 32])>,
    m3: Vec<([u8; 8], [u8; 32], Vec<u8>)>,
    m2: Vec<([u8; 8], Vec<u8>)>,
    m4: Vec<([u8; 8], Vec<u8>)>,
}

struct AssocPmkid {
    access_point: [u8; 6],
    station: [u8; 6],
    essid: Vec<u8>,
    pmkid: [u8; 16],
}

#[derive(Default)]
struct Capture {
    essids: BTreeMap<[u8; 6], Vec<u8>>,
    sessions: BTreeMap<([u8; 6], [u8; 6]), Session>,
    assoc_pmkids: Vec<AssocPmkid>,
}

fn address(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    frame.get(offset..offset + 6)?.try_into().ok()
}

fn information_elements(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut elements = Vec::new();
    while data.len() >= 2 {
        let id = data[0];
        let length = usize::from(data[1]);
        let Some(value) = data.get(2..2 + length) else {
            break;
        };
        elements.push((id, value));
        data = &data[2 + length..];
    }
    elements
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let value = self.data.get(self.offset..self.offset + length)?;
        self.offset += length;
        Some(value)
    }

    fn u16(&mut self) -> Option<usize> {
        let value = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([value[0], value[1]])))
    }
}

fn rsn_pmkids(data: &[u8]) -> Vec<[u8; 16]> {
    let mut pmkids = Vec::new();
    let mut cursor = Cursor::new(data);
    let Some(version) = cursor.u16() else {
        return pmkids;
    };
    if version != 1 {
        return pmkids;
    }
    if cursor.take(4).is_none() {
        return pmkids;
    }
    let Some(pairwise) = cursor.u16() else {
        return pmkids;
    };
    if cursor.take(pairwise * 4).is_none() {
        return pmkids;
    }
    let Some(akm) = cursor.u16() else {
        return pmkids;
    };
    if cursor.take(akm * 4).is_none() {
        return pmkids;
    }
    if cursor.take(2).is_none() {
        return pmkids;
    }
    let Some(count) = cursor.u16() else {
        return pmkids;
    };
    for _ in 0..count {
        let Some(pmkid) = cursor.take(16) else {
            break;
        };
        if let Ok(pmkid) = pmkid.try_into() {
            pmkids.push(pmkid);
        }
    }
    pmkids
}

fn key_data_pmkids(data: &[u8]) -> Vec<[u8; 16]> {
    let mut pmkids = Vec::new();
    let mut offset = 0usize;
    while offset + 2 <= data.len() {
        let id = data[offset];
        let length = usize::from(data[offset + 1]);
        let Some(value) = data.get(offset + 2..offset + 2 + length) else {
            break;
        };
        if id == 0xdd && length == 20 && value[..4] == [0x00, 0x0f, 0xac, 0x04] {
            if let Ok(pmkid) = value[4..20].try_into() {
                pmkids.push(pmkid);
            }
        }
        offset += 2 + length;
    }
    pmkids
}

fn management(
    subtype: u8,
    body: &[u8],
    address1: [u8; 6],
    address2: [u8; 6],
    capture: &mut Capture,
) {
    let fixed = match subtype {
        0 | 2 => 4,
        5 | 8 => 12,
        _ => return,
    };
    let Some(ies) = body.get(fixed..) else {
        return;
    };
    let mut essid = None;
    let mut pmkids = Vec::new();
    for (id, value) in information_elements(ies) {
        match id {
            0 if !value.is_empty() => essid = Some(value.to_vec()),
            48 => pmkids.extend(rsn_pmkids(value)),
            _ => {}
        }
    }
    let Some(essid) = essid else {
        return;
    };
    match subtype {
        0 | 2 => {
            capture.essids.insert(address1, essid.clone());
            for pmkid in pmkids {
                capture.assoc_pmkids.push(AssocPmkid {
                    access_point: address1,
                    station: address2,
                    essid: essid.clone(),
                    pmkid,
                });
            }
        }
        _ => {
            capture.essids.insert(address2, essid);
        }
    }
}

fn eapol_key(access_point: [u8; 6], station: [u8; 6], eapol: &[u8], capture: &mut Capture) {
    if eapol.len() < 4 || !matches!(eapol[0], 1 | 2) || eapol[1] != 3 {
        return;
    }
    let length = usize::from(u16::from_be_bytes([eapol[2], eapol[3]]));
    if length < 95 {
        return;
    }
    let Some(frame) = eapol.get(..4 + length) else {
        return;
    };
    let body = &frame[4..];
    if body[0] != 2 {
        return;
    }
    let key_info = u16::from_be_bytes([body[1], body[2]]);
    let ack = key_info & 0x0080 != 0;
    let mic = key_info & 0x0100 != 0;
    let install = key_info & 0x0040 != 0;
    let secure = key_info & 0x0200 != 0;
    let Some(nonce) = body.get(13..45).and_then(|value| value.try_into().ok()) else {
        return;
    };
    let Some(replay) = body.get(5..13).and_then(|value| value.try_into().ok()) else {
        return;
    };
    let key_data_length = usize::from(u16::from_be_bytes([body[93], body[94]]));
    let key_data = body.get(95..95 + key_data_length).unwrap_or(&[]);

    let session = capture.sessions.entry((access_point, station)).or_default();
    match (ack, mic, install, secure) {
        (true, false, false, false) => {
            if !session.m1.iter().any(|entry| entry.0 == replay) {
                session.m1.push((replay, nonce));
            }
            for pmkid in key_data_pmkids(key_data) {
                if !session.pmkids.contains(&pmkid) {
                    session.pmkids.push(pmkid);
                }
            }
        }
        (false, true, false, false) => session.m2.push((replay, frame.to_vec())),
        (true, true, true, _) => {
            if !session.m3.iter().any(|entry| entry.0 == replay) {
                session.m3.push((replay, nonce, frame.to_vec()));
            }
        }
        (false, true, false, true) => session.m4.push((replay, frame.to_vec())),
        _ => {}
    }
}

fn dot11(link_type: u32, frame: &[u8], capture: &mut Capture) {
    let Some(frame) = net::dot11(link_type, frame) else {
        return;
    };
    let Some(control) = frame.get(..2) else {
        return;
    };
    let control = u16::from_le_bytes([control[0], control[1]]);
    if control & 0x0003 != 0 {
        return;
    }
    let kind = (control >> 2) & 0x3;
    let subtype = ((control >> 4) & 0xf) as u8;
    let flags = (control >> 8) as u8;
    if flags & 0x40 != 0 {
        return;
    }
    let Some(header) = net::dot11_header_len(frame) else {
        return;
    };
    let Some(body) = frame.get(header..) else {
        return;
    };
    let Some(address1) = address(frame, 4) else {
        return;
    };
    let Some(address2) = address(frame, 10) else {
        return;
    };
    match kind {
        0 => management(subtype, body, address1, address2, capture),
        2 => {
            let (access_point, station) = match (flags & 0x01 != 0, flags & 0x02 != 0) {
                (true, false) => (address1, address2),
                (false, true) => (address2, address1),
                _ => return,
            };
            let Some(llc) = body.strip_prefix(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]) else {
                return;
            };
            if llc.get(..2) != Some(&[0x88, 0x8e]) {
                return;
            }
            eapol_key(access_point, station, &llc[2..], capture);
        }
        _ => {}
    }
}

fn scan_capture(artifact: &Artifact) -> Result<Capture, ExtractError> {
    let source = artifact.primary();
    if !net::is_capture(source) {
        return Err(ExtractError::Unsupported("not a packet capture".to_owned()));
    }
    let mut capture = Capture::default();
    net::scan(source, |link_type, frame| {
        if link_type == net::LINKTYPE_IEEE802_11 || link_type == net::LINKTYPE_RADIOTAP {
            dot11(link_type, frame, &mut capture);
        }
    })?;
    Ok(capture)
}

fn pmkid_values(capture: &Capture) -> Vec<PmkidRecord> {
    let mut records = BTreeSet::new();
    for entry in &capture.assoc_pmkids {
        records.insert((
            entry.access_point,
            entry.station,
            entry.pmkid,
            entry.essid.clone(),
        ));
    }
    for ((access_point, station), session) in &capture.sessions {
        let Some(essid) = capture.essids.get(access_point) else {
            continue;
        };
        for pmkid in &session.pmkids {
            records.insert((*access_point, *station, *pmkid, essid.clone()));
        }
    }
    records.into_iter().collect()
}

fn mic(frame: &[u8]) -> Option<[u8; 16]> {
    frame.get(81..97)?.try_into().ok()
}

fn eapol_values(capture: &Capture) -> Vec<EapolRecord> {
    let mut records = BTreeSet::new();
    for ((access_point, station), session) in &capture.sessions {
        if !capture.essids.contains_key(access_point) {
            continue;
        }
        let mut frames = Vec::new();
        for (replay, frame) in &session.m2 {
            if let Some((_, nonce)) = session.m1.iter().find(|entry| entry.0 == *replay) {
                frames.push((*nonce, frame, 0));
            }
            for (m3_replay, nonce, _) in &session.m3 {
                if m3_replay == replay {
                    frames.push((*nonce, frame, 2));
                }
            }
        }
        for (replay, frame) in &session.m4 {
            if let Some((_, nonce)) = session.m1.iter().find(|entry| entry.0 == *replay) {
                frames.push((*nonce, frame, 1));
            }
            for (m3_replay, nonce, _) in &session.m3 {
                if m3_replay == replay {
                    frames.push((*nonce, frame, 4));
                }
            }
        }
        for (_, nonce, frame) in &session.m3 {
            frames.push((*nonce, frame, 3));
        }
        for (nonce, frame, pair) in frames {
            if let Some(mic) = mic(frame) {
                records.insert((*access_point, *station, mic, nonce, frame.clone(), pair));
            }
        }
    }
    records.into_iter().collect()
}

fn build(capture: &Capture) -> Vec<WpaPmkid> {
    let mut values = Vec::new();
    for (access_point, station, pmkid, essid) in pmkid_values(capture) {
        values.push(WpaPmkid {
            kind: KIND_PMKID.to_owned(),
            pmkid,
            access_point,
            station,
            essid,
            extras: "**".to_owned(),
        });
    }
    for (access_point, station, mic, nonce, frame, pair) in eapol_values(capture) {
        let Some(essid) = capture.essids.get(&access_point) else {
            continue;
        };
        values.push(WpaPmkid {
            kind: KIND_EAPOL.to_owned(),
            pmkid: mic,
            access_point,
            station,
            essid: essid.clone(),
            extras: format!(
                "{}*{}*{:02x}",
                crate::format::hex(nonce),
                crate::format::hex(&frame),
                pair
            ),
        });
    }
    values
}

fn probe_capture(artifact: &Artifact) -> Probe {
    if !net::is_capture(artifact.primary()) {
        return Probe::No;
    }
    match scan_capture(artifact) {
        Ok(capture) => {
            let pmkid = !pmkid_values(&capture).is_empty();
            let eapol = !eapol_values(&capture).is_empty();
            match (pmkid, eapol) {
                (true, true) => Probe::yes("WPA PMKID and EAPOL records"),
                (true, false) => Probe::yes("WPA PMKID records"),
                (false, true) => Probe::yes("WPA EAPOL records"),
                (false, false) => Probe::No,
            }
        }
        Err(ExtractError::Unsupported(_)) => Probe::No,
        Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
    }
}

pub struct WpaPmkidExtractor;

impl Extractor for WpaPmkidExtractor {
    fn slug(&self) -> &'static str {
        WpaPmkid::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_capture(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let capture = scan_capture(artifact)?;
        let values = build(&capture);
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no WPA handshake or PMKID records".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}

pub(crate) fn scan_for_pmkids(artifact: &Artifact) -> Result<Vec<PmkidRecord>, ExtractError> {
    Ok(pmkid_values(&scan_capture(artifact)?))
}
