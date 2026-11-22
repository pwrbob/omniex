//! IKEv1 aggressive-mode pre-shared-key extraction (MD5).

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::IkePskMd5;
use omniex::{HashType, HashValue, Render};

pub(crate) mod ike {
    //! IKEv1 aggressive-mode payload decoding shared by the IKE extractors.

    use std::collections::BTreeMap;

    use omniex::extract::{Artifact, ExtractError, ReadAt};

    const IKE_PORT: u16 = 500;
    const IKE_NAT_PORT: u16 = 4500;
    const IKEV1_AGGRESSIVE: u8 = 4;

    const PAYLOAD_SA: u8 = 1;
    const PAYLOAD_KE: u8 = 4;
    const PAYLOAD_ID: u8 = 5;
    const PAYLOAD_HASH: u8 = 8;
    const PAYLOAD_NONCE: u8 = 10;

    const LINKTYPE_ETHERNET: u32 = 1;
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

    /// One complete aggressive-mode exchange.
    pub(crate) struct Exchange {
        /// Responder key-exchange value.
        pub(crate) g_xr: Vec<u8>,
        /// Initiator key-exchange value.
        pub(crate) g_xi: Vec<u8>,
        /// Responder cookie.
        pub(crate) cky_r: [u8; 8],
        /// Initiator cookie.
        pub(crate) cky_i: [u8; 8],
        /// Initiator SA payload body.
        pub(crate) sai_b: Vec<u8>,
        /// Responder identification payload body.
        pub(crate) idir_b: Vec<u8>,
        /// Initiator nonce payload body.
        pub(crate) ni_b: Vec<u8>,
        /// Responder nonce payload body.
        pub(crate) nr_b: Vec<u8>,
        /// Responder HASH payload body.
        pub(crate) hash_r: Vec<u8>,
    }

    impl Exchange {
        /// Renders the John `$ike$*0*` serialization.
        pub(crate) fn john_fields(&self) -> String {
            format!(
                "*0*{}*{}*{}*{}*{}*{}*{}*{}*{}",
                omniex::format::hex(&self.g_xr),
                omniex::format::hex(&self.g_xi),
                omniex::format::hex(self.cky_r),
                omniex::format::hex(self.cky_i),
                omniex::format::hex(&self.sai_b),
                omniex::format::hex(&self.idir_b),
                omniex::format::hex(&self.ni_b),
                omniex::format::hex(&self.nr_b),
                omniex::format::hex(&self.hash_r)
            )
        }
    }

    struct Packet {
        cky_i: [u8; 8],
        cky_r: [u8; 8],
        sa: Option<Vec<u8>>,
        ke: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        id: Option<Vec<u8>>,
        hash: Option<Vec<u8>>,
    }

    fn truncated() -> ExtractError {
        ExtractError::Invalid("truncated packet capture".to_owned())
    }

    fn not_capture() -> ExtractError {
        ExtractError::Unsupported("not a packet capture".to_owned())
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

    /// Returns whether the source starts with a supported capture signature.
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

    fn scan_capture<F>(source: &dyn ReadAt, mut visit: F) -> Result<(), ExtractError>
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
        while offset < len {
            if offset + 16 > len {
                return Err(truncated());
            }
            let captured = u64::from(u32_at(source, offset + 8, big_endian)?);
            offset += 16;
            if offset + captured > len {
                return Err(truncated());
            }
            if captured <= MAX_PACKET {
                buffer.resize(captured as usize, 0);
                source
                    .read_exact_at(offset, &mut buffer)
                    .map_err(|_| truncated())?;
                visit(link_type, &buffer);
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
                    if let Some(link_type) = interfaces.get(interface)
                        && captured <= MAX_PACKET
                        && 20 + captured <= body
                    {
                        buffer.resize(captured as usize, 0);
                        source
                            .read_exact_at(offset + 28, &mut buffer)
                            .map_err(|_| truncated())?;
                        visit(*link_type, &buffer);
                    }
                }
                3 if body >= 4 => {
                    let original = u64::from(u32_at(source, offset + 8, big_endian)?);
                    let length = original.min(body - 4).min(MAX_PACKET);
                    if let Some(link_type) = interfaces.first().copied()
                        && length > 0
                    {
                        buffer.resize(length as usize, 0);
                        source
                            .read_exact_at(offset + 12, &mut buffer)
                            .map_err(|_| truncated())?;
                        visit(link_type, &buffer);
                    }
                }
                _ => {}
            }
            offset += total;
        }
        Ok(())
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

    fn ip_payload(link_type: u32, frame: &[u8]) -> Option<(u8, &[u8])> {
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

    fn payloads(data: &[u8]) -> Option<Packet> {
        if data.len() < 28 {
            return None;
        }
        let version = data[17];
        if version >> 4 != 1 || data[18] != IKEV1_AGGRESSIVE {
            return None;
        }
        let total =
            usize::try_from(u32::from_be_bytes([data[24], data[25], data[26], data[27]])).ok()?;
        if total < 28 || total > data.len() {
            return None;
        }
        let mut packet = Packet {
            cky_i: data[..8].try_into().ok()?,
            cky_r: data[8..16].try_into().ok()?,
            sa: None,
            ke: None,
            nonce: None,
            id: None,
            hash: None,
        };
        let mut next = data[16];
        let mut offset = 28;
        while next != 0 {
            if offset + 4 > total {
                return None;
            }
            let length = usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
            if length < 4 || offset + length > total {
                return None;
            }
            let body = data[offset + 4..offset + length].to_vec();
            match next {
                PAYLOAD_SA => packet.sa = Some(body),
                PAYLOAD_KE => packet.ke = Some(body),
                PAYLOAD_ID => packet.id = Some(body),
                PAYLOAD_HASH => packet.hash = Some(body),
                PAYLOAD_NONCE => packet.nonce = Some(body),
                _ => {}
            }
            next = data[offset];
            offset += length;
        }
        Some(packet)
    }

    fn ike_payload(port: u16, data: &[u8]) -> &[u8] {
        if port == IKE_NAT_PORT && data.len() >= 4 && data[..4] == [0, 0, 0, 0] {
            &data[4..]
        } else {
            data
        }
    }

    /// Scans a capture for complete IKEv1 aggressive-mode exchanges.
    ///
    /// The boolean reports whether any IKEv1 aggressive-mode packet was seen,
    /// even when no complete exchange could be assembled.
    pub(crate) fn scan(artifact: &Artifact) -> Result<(Vec<Exchange>, bool), ExtractError> {
        let mut initiators: BTreeMap<[u8; 8], Packet> = BTreeMap::new();
        let mut responders: BTreeMap<([u8; 8], [u8; 8]), Packet> = BTreeMap::new();
        let mut saw_ike = false;

        scan_capture(artifact.primary(), |link_type, frame| {
            let Some((protocol, data)) = ip_payload(link_type, frame) else {
                return;
            };
            if protocol != 17 {
                return;
            }
            let Some((source, destination, data)) = udp(data) else {
                return;
            };
            let port = if source == IKE_PORT || source == IKE_NAT_PORT {
                source
            } else if destination == IKE_PORT || destination == IKE_NAT_PORT {
                destination
            } else {
                return;
            };
            let Some(packet) = payloads(ike_payload(port, data)) else {
                return;
            };
            saw_ike = true;
            if packet.cky_r == [0; 8] {
                if packet.sa.is_some() && packet.ke.is_some() && packet.nonce.is_some() {
                    initiators.entry(packet.cky_i).or_insert(packet);
                }
            } else if packet.ke.is_some()
                && packet.nonce.is_some()
                && packet.id.is_some()
                && packet.hash.is_some()
            {
                responders
                    .entry((packet.cky_i, packet.cky_r))
                    .or_insert(packet);
            }
        })?;

        let mut exchanges = Vec::new();
        for ((cky_i, cky_r), responder) in responders {
            let Some(initiator) = initiators.get(&cky_i) else {
                continue;
            };
            let (Some(g_xi), Some(ni_b), Some(sai_b)) = (
                initiator.ke.clone(),
                initiator.nonce.clone(),
                initiator.sa.clone(),
            ) else {
                continue;
            };
            let (Some(g_xr), Some(nr_b), Some(idir_b), Some(hash_r)) = (
                responder.ke.clone(),
                responder.nonce.clone(),
                responder.id.clone(),
                responder.hash.clone(),
            ) else {
                continue;
            };
            exchanges.push(Exchange {
                g_xr,
                g_xi,
                cky_r,
                cky_i,
                sai_b,
                idir_b,
                ni_b,
                nr_b,
                hash_r,
            });
        }
        Ok((exchanges, saw_ike))
    }
}

fn scan_records(artifact: &Artifact) -> Result<Vec<IkePskMd5>, ExtractError> {
    let (exchanges, _) = ike::scan(artifact)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut values = Vec::new();
    for exchange in exchanges {
        if exchange.hash_r.len() != 16 {
            continue;
        }
        let Ok(digest) = exchange.hash_r.as_slice().try_into() else {
            continue;
        };
        let value = IkePskMd5 {
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
            if exchanges.iter().any(|exchange| exchange.hash_r.len() == 16) {
                Probe::yes("IKEv1 aggressive-mode MD5 exchange")
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

/// Extractor for IKEv1 aggressive-mode MD5 hashes.
pub struct IkePskMd5Extractor;

impl Extractor for IkePskMd5Extractor {
    fn slug(&self) -> &'static str {
        IkePskMd5::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        probe_records(artifact)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = scan_records(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no IKEv1 aggressive-mode MD5 exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
