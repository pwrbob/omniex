//! iSCSI CHAP MD5 extraction from packet captures.
//!
//! The bounded capture reader lives in [`capture`] so the other network
//! protocol extractors in this batch decode the same containers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::IscsiChap;
use crate::{HashType, HashValue};

pub(crate) mod capture {
    //! Streaming packet-capture reader for classic pcap and pcapng files.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::extract::{ExtractError, ReadAt};

    const LINKTYPE_ETHERNET: u32 = 1;
    const LINKTYPE_RAW: u32 = 101;
    const LINKTYPE_RAW_ALT: u32 = 12;
    const LINKTYPE_IPV4: u32 = 228;
    const LINKTYPE_IPV6: u32 = 229;
    const LINKTYPE_LINUX_SLL: u32 = 113;
    const LINKTYPE_LINUX_SLL2: u32 = 276;

    const MAX_FRAME: u64 = 262_144;
    const MAX_BLOCK: u64 = 64 * 1024 * 1024;

    const PCAP_MAGIC_USEC_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
    const PCAP_MAGIC_USEC_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
    const PCAP_MAGIC_NSEC_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
    const PCAP_MAGIC_NSEC_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
    const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

    /// Transport protocol of a captured datagram.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Protocol {
        /// User Datagram Protocol.
        Udp,
        /// Transmission Control Protocol.
        Tcp,
    }

    /// One transport payload from a capture.
    pub(crate) struct Datagram<'a> {
        /// One-based packet index in capture order.
        pub(crate) index: u64,
        /// Source address.
        pub(crate) source: SocketAddr,
        /// Destination address.
        pub(crate) destination: SocketAddr,
        /// Transport protocol.
        pub(crate) protocol: Protocol,
        /// Transport payload.
        pub(crate) payload: &'a [u8],
    }

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
        matches!(
            magic,
            PCAP_MAGIC_USEC_LE
                | PCAP_MAGIC_USEC_BE
                | PCAP_MAGIC_NSEC_LE
                | PCAP_MAGIC_NSEC_BE
                | PCAPNG_MAGIC
        )
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

    /// Visits every transport payload in the capture.
    pub(crate) fn scan_datagrams<F>(source: &dyn ReadAt, mut visit: F) -> Result<(), ExtractError>
    where
        F: FnMut(&Datagram<'_>),
    {
        let len = source.len();
        let mut magic = [0u8; 4];
        source
            .read_exact_at(0, &mut magic)
            .map_err(|_| not_capture())?;
        let mut index = 0u64;
        match magic {
            PCAP_MAGIC_USEC_LE => scan_classic(source, len, false, &mut index, &mut visit),
            PCAP_MAGIC_USEC_BE => scan_classic(source, len, true, &mut index, &mut visit),
            PCAP_MAGIC_NSEC_LE => scan_classic(source, len, false, &mut index, &mut visit),
            PCAP_MAGIC_NSEC_BE => scan_classic(source, len, true, &mut index, &mut visit),
            PCAPNG_MAGIC => scan_ng(source, len, &mut index, &mut visit),
            _ => Err(not_capture()),
        }
    }

    fn scan_classic<F>(
        source: &dyn ReadAt,
        len: u64,
        big_endian: bool,
        index: &mut u64,
        visit: &mut F,
    ) -> Result<(), ExtractError>
    where
        F: FnMut(&Datagram<'_>),
    {
        if len < 24 {
            return Err(truncated());
        }
        let link_type = u32_at(source, 20, big_endian)?;
        let mut offset = 24u64;
        let mut buffer = Vec::new();
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
                if len - offset > 1 {
                    return Err(truncated());
                }
                break;
            }
            if captured <= MAX_FRAME {
                buffer.resize(captured as usize, 0);
                source
                    .read_exact_at(offset, &mut buffer)
                    .map_err(|_| truncated())?;
                *index += 1;
                deliver(link_type, &buffer, *index, visit);
            }
            offset += captured;
        }
        Ok(())
    }

    fn scan_ng<F>(
        source: &dyn ReadAt,
        len: u64,
        index: &mut u64,
        visit: &mut F,
    ) -> Result<(), ExtractError>
    where
        F: FnMut(&Datagram<'_>),
    {
        let mut interfaces: Vec<u32> = Vec::new();
        let mut offset = 0u64;
        let mut header = [0u8; 8];
        while offset < len {
            if offset + 12 > len {
                return Err(truncated());
            }
            source
                .read_exact_at(offset, &mut header)
                .map_err(|_| truncated())?;
            let block_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let total = u64::from(u32::from_le_bytes([
                header[4], header[5], header[6], header[7],
            ]));
            if !(12..=MAX_BLOCK).contains(&total) || offset + total > len || total % 4 != 0 {
                return Err(truncated());
            }
            let body_len = (total - 12) as usize;
            let mut body = vec![0u8; body_len];
            source
                .read_exact_at(offset + 8, &mut body)
                .map_err(|_| truncated())?;
            match block_type {
                0x0a0d_0d0a => {
                    if body.len() < 4 {
                        return Err(truncated());
                    }
                    let order = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    if order != 0x1a2b_3c4d {
                        return Err(ExtractError::Unsupported(
                            "big-endian pcapng captures are not supported".to_owned(),
                        ));
                    }
                }
                1 => {
                    if body.len() < 8 {
                        return Err(truncated());
                    }
                    interfaces.push(u32::from(u16::from_le_bytes([body[0], body[1]])));
                }
                3 => {
                    if body.len() < 4 {
                        return Err(truncated());
                    }
                    let Some(link_type) = interfaces.first().copied() else {
                        return Err(truncated());
                    };
                    let captured =
                        usize::try_from(u32::from_le_bytes([body[0], body[1], body[2], body[3]]))
                            .unwrap_or(usize::MAX);
                    if captured <= MAX_FRAME as usize && body.len() >= 4 + captured {
                        *index += 1;
                        deliver(link_type, &body[4..4 + captured], *index, visit);
                    }
                }
                6 => {
                    if body.len() < 20 {
                        return Err(truncated());
                    }
                    let interface = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let captured = usize::try_from(u32::from_le_bytes([
                        body[12], body[13], body[14], body[15],
                    ]))
                    .unwrap_or(usize::MAX);
                    let Some(link_type) = interfaces.get(interface as usize).copied() else {
                        return Err(truncated());
                    };
                    if captured <= MAX_FRAME as usize && body.len() >= 20 + captured {
                        *index += 1;
                        deliver(link_type, &body[20..20 + captured], *index, visit);
                    }
                }
                _ => {}
            }
            offset += total;
        }
        Ok(())
    }

    fn deliver<F>(link_type: u32, frame: &[u8], index: u64, visit: &mut F)
    where
        F: FnMut(&Datagram<'_>),
    {
        let Some((ethertype, data)) = link_payload(link_type, frame) else {
            return;
        };
        let Some((protocol, source, destination, payload)) = ip_datagram(ethertype, data) else {
            return;
        };
        visit(&Datagram {
            index,
            source,
            destination,
            protocol,
            payload,
        });
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
                Some((if version == 6 { 0x86dd } else { 0x0800 }, frame))
            }
            LINKTYPE_IPV4 => Some((0x0800, frame)),
            LINKTYPE_IPV6 => Some((0x86dd, frame)),
            _ => None,
        }
    }

    fn ip_datagram(
        ethertype: u16,
        data: &[u8],
    ) -> Option<(Protocol, SocketAddr, SocketAddr, &[u8])> {
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
                let protocol = data[9];
                let source = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
                let destination = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
                transport(protocol, source, destination, &data[header..total])
            }
            0x86dd => {
                if data.len() < 40 || data[0] >> 4 != 6 {
                    return None;
                }
                let total = 40 + usize::from(u16::from_be_bytes([data[4], data[5]]));
                let end = total.min(data.len());
                let source =
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?));
                let destination = IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(data.get(24..40)?).ok()?,
                ));
                let mut next = data[6];
                let mut rest = data.get(40..end)?;
                while matches!(next, 0 | 43 | 60) {
                    let length = (usize::from(*rest.get(1)?) + 1) * 8;
                    next = *rest.first()?;
                    rest = rest.get(length..)?;
                }
                if next == 44 {
                    return None;
                }
                transport(next, source, destination, rest)
            }
            _ => None,
        }
    }

    fn transport(
        protocol: u8,
        source: IpAddr,
        destination: IpAddr,
        data: &[u8],
    ) -> Option<(Protocol, SocketAddr, SocketAddr, &[u8])> {
        match protocol {
            17 => {
                if data.len() < 8 {
                    return None;
                }
                let source_port = u16::from_be_bytes([data[0], data[1]]);
                let destination_port = u16::from_be_bytes([data[2], data[3]]);
                let length = usize::from(u16::from_be_bytes([data[4], data[5]]));
                if length < 8 || length > data.len() {
                    return None;
                }
                Some((
                    Protocol::Udp,
                    SocketAddr::new(source, source_port),
                    SocketAddr::new(destination, destination_port),
                    &data[8..length],
                ))
            }
            6 => {
                if data.len() < 20 {
                    return None;
                }
                let source_port = u16::from_be_bytes([data[0], data[1]]);
                let destination_port = u16::from_be_bytes([data[2], data[3]]);
                let header = usize::from(data[12] >> 4) * 4;
                if header < 20 || header > data.len() {
                    return None;
                }
                Some((
                    Protocol::Tcp,
                    SocketAddr::new(source, source_port),
                    SocketAddr::new(destination, destination_port),
                    &data[header..],
                ))
            }
            _ => None,
        }
    }
}

use capture::{Protocol, scan_datagrams};

const ISCSI_PORT: u16 = 3260;
const CHAP_ALGORITHM_MD5: &str = "5";
const MAX_STREAM: usize = 1024 * 1024;

#[derive(Default)]
struct Direction {
    buffer: Vec<u8>,
}

#[derive(Default)]
struct Connection {
    directions: BTreeMap<SocketAddr, Direction>,
    challenge: Option<(Vec<u8>, Vec<u8>)>,
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn text_keys(data: &[u8]) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    for entry in data.split(|byte| *byte == 0) {
        let Ok(text) = std::str::from_utf8(entry) else {
            continue;
        };
        if let Some((key, value)) = text.split_once('=') {
            keys.insert(key.trim().to_ascii_uppercase(), value.trim().to_owned());
        }
    }
    keys
}

fn chap_id(text: &str) -> Result<u8, ()> {
    text.parse::<u8>().map_err(|_| ())
}

/// One digest, challenge, and CHAP identifier triple.
type HashRecord = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Extracts iSCSI CHAP MD5 exchanges from a packet capture.
pub struct IscsiChapExtractor;

fn scan(artifact: &Artifact) -> Result<(BTreeSet<HashRecord>, bool), ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not an iSCSI CHAP capture".to_owned(),
        ));
    }
    let mut connections: BTreeMap<(SocketAddr, SocketAddr), Connection> = BTreeMap::new();
    let mut records = BTreeSet::new();
    let mut seen = false;
    scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Tcp {
            return;
        }
        if datagram.source.port() != ISCSI_PORT && datagram.destination.port() != ISCSI_PORT {
            return;
        }
        seen = true;
        let key = if datagram.source < datagram.destination {
            (datagram.source, datagram.destination)
        } else {
            (datagram.destination, datagram.source)
        };
        let connection = connections.entry(key).or_default();
        let direction = connection.directions.entry(datagram.source).or_default();
        direction.buffer.extend_from_slice(datagram.payload);
        while direction.buffer.len() >= 48 {
            let length = u32::from_be_bytes([
                direction.buffer[4],
                direction.buffer[5],
                direction.buffer[6],
                direction.buffer[7],
            ]);
            let ahs = usize::from(direction.buffer[4]) * 4;
            let total = 48 + ahs + usize::try_from(length & 0x00ff_ffff).unwrap_or(usize::MAX);
            if total > MAX_STREAM || direction.buffer.len() < total {
                break;
            }
            let pdu = direction.buffer[..total].to_vec();
            direction.buffer.drain(..total);
            let fields = text_keys(pdu.get(48 + ahs..).unwrap_or_default());
            if let Some(algorithm) = fields.get("CHAP_A") {
                if algorithm != CHAP_ALGORITHM_MD5 {
                    continue;
                }
            }
            if let (Some(challenge), Some(identifier)) =
                (fields.get("CHAP_C"), fields.get("CHAP_I"))
            {
                if let (Some(challenge), Ok(identifier)) =
                    (decode_hex(challenge), chap_id(identifier))
                {
                    connection.challenge = Some((challenge, vec![identifier]));
                }
            }
            let response = fields
                .get("CHAP_R")
                .and_then(|value| decode_hex(value))
                .filter(|digest| digest.len() == 16);
            if let (Some(digest), Some((challenge, chap_id))) =
                (response, connection.challenge.as_ref())
            {
                records.insert((digest, challenge.clone(), chap_id.clone()));
            }
        }
        if direction.buffer.len() > MAX_STREAM {
            direction.buffer.clear();
        }
    })?;
    Ok((records, seen))
}

impl Extractor for IscsiChapExtractor {
    fn slug(&self) -> &'static str {
        IscsiChap::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok((records, _)) if !records.is_empty() => Probe::yes("iSCSI CHAP MD5 login exchange"),
            Ok((_, true)) => {
                Probe::Maybe("iSCSI capture without a complete CHAP exchange".to_owned())
            }
            Ok((_, false)) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let (records, _) = scan(artifact)?;
        if records.is_empty() {
            return Err(ExtractError::Unsupported(
                "no iSCSI CHAP exchanges".to_owned(),
            ));
        }
        Ok(records
            .into_iter()
            .map(|(digest, challenge, chap_id)| {
                let mut record = IscsiChap {
                    digest: [0; 16],
                    challenge,
                    chap_id,
                };
                record.digest.copy_from_slice(&digest);
                Box::new(record) as Box<dyn HashValue>
            })
            .collect())
    }
}
