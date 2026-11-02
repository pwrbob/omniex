//! SNMPv3 USM authenticated message extraction.
//!
//! Each message is re-serialized with `msgAuthenticationParameters` zeroed so
//! the captured HMAC can be attacked as a `$SNMPv3$` hash.

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Snmpv3;
use crate::{HashType, HashValue};
use std::collections::BTreeSet;

const SNMP_PORTS: [u16; 2] = [161, 162];
const MAX_MESSAGE: u64 = 1024 * 1024;

/// Extracts SNMPv3 USM authenticated messages from a packet capture.
pub struct Snmpv3Extractor;

#[derive(Debug, Clone)]
struct Message {
    submode: u8,
    packet_number: String,
    message: String,
    engine_id: String,
    digest: Vec<u8>,
}

fn tlv(data: &[u8], offset: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *data.get(offset)?;
    let first = *data.get(offset + 1)?;
    let (length, body) = if first & 0x80 == 0 {
        (usize::from(first), offset + 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(offset + 2..offset + 2 + count)?;
        let mut length = 0usize;
        for byte in bytes {
            length = (length << 8) | usize::from(*byte);
        }
        (length, offset + 2 + count)
    };
    if length > data.len().checked_sub(body)? {
        return None;
    }
    Some((tag, body, length, body + length))
}

fn integer(data: &[u8], start: usize, length: usize) -> Option<u64> {
    let bytes = data.get(start..start + length)?;
    if bytes.is_empty() || bytes.len() > 8 || bytes[0] & 0x80 != 0 {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

fn submode(auth_length: usize) -> Option<u8> {
    match auth_length {
        12 => Some(0),
        16 => Some(3),
        24 => Some(4),
        32 => Some(5),
        48 => Some(6),
        _ => None,
    }
}

fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn parse_message(data: &[u8], packet_number: &str) -> Option<Message> {
    let (tag, start, length, end) = tlv(data, 0)?;
    if tag != 0x30 || end != data.len() {
        return None;
    }
    let outer_end = start + length;
    let (tag, version_start, version_len, mut cursor) = tlv(data, start)?;
    if tag != 0x02 || cursor > outer_end || integer(data, version_start, version_len)? != 3 {
        return None;
    }
    let (tag, global_start, global_len, next) = tlv(data, cursor)?;
    if tag != 0x30 {
        return None;
    }
    cursor = next;

    let mut global = global_start;
    let global_end = global_start + global_len;
    let (tag, _, _, next) = tlv(data, global)?;
    if tag != 0x02 {
        return None;
    }
    global = next;
    let (tag, _, _, next) = tlv(data, global)?;
    if tag != 0x02 {
        return None;
    }
    global = next;
    let (tag, flags_start, flags_len, next) = tlv(data, global)?;
    if tag != 0x04 || flags_len == 0 {
        return None;
    }
    let authenticated = data.get(flags_start).is_some_and(|flags| flags & 0x01 != 0);
    global = next;
    let (tag, model_start, model_len, next) = tlv(data, global)?;
    if tag != 0x02 || integer(data, model_start, model_len)? != 3 || next > global_end {
        return None;
    }

    let (tag, security_start, security_len, _) = tlv(data, cursor)?;
    if tag != 0x04 {
        return None;
    }
    let security_end = security_start + security_len;
    let (tag, parameters_start, parameters_len, _) = tlv(data, security_start)?;
    if tag != 0x30 || parameters_start + parameters_len > security_end {
        return None;
    }

    let mut parameters = parameters_start;
    let parameters_end = parameters_start + parameters_len;
    let (tag, engine_start, engine_len, next) = tlv(data, parameters)?;
    if tag != 0x04 {
        return None;
    }
    let engine_id = hex(data.get(engine_start..engine_start + engine_len)?);
    parameters = next;
    for _ in 0..2 {
        let (tag, _, _, next) = tlv(data, parameters)?;
        if tag != 0x02 {
            return None;
        }
        parameters = next;
    }
    let (tag, user_start, user_len, next) = tlv(data, parameters)?;
    if tag != 0x04 {
        return None;
    }
    let user = data.get(user_start..user_start + user_len)?;
    parameters = next;
    let (tag, auth_start, auth_len, _) = tlv(data, parameters)?;
    if tag != 0x04 {
        return None;
    }
    if !(5..=32).contains(&engine_len) || auth_start + auth_len > parameters_end {
        return None;
    }
    if !authenticated || auth_len == 0 || user.is_empty() {
        return None;
    }
    let submode = submode(auth_len)?;
    let digest = data.get(auth_start..auth_start + auth_len)?.to_vec();
    let mut zeroed = data.to_vec();
    zeroed.get_mut(auth_start..auth_start + auth_len)?.fill(0);
    Some(Message {
        submode,
        packet_number: packet_number.to_owned(),
        message: hex(&zeroed),
        engine_id,
        digest,
    })
}

fn snmp_version(data: &[u8]) -> Option<u64> {
    let (tag, start, length, end) = tlv(data, 0)?;
    if tag != 0x30 || end > data.len() {
        return None;
    }
    let (tag, version_start, version_len, _) = tlv(data, start)?;
    if tag != 0x02 || start + length < version_start + version_len {
        return None;
    }
    integer(data, version_start, version_len)
}

fn scan(artifact: &Artifact) -> Result<(Vec<Message>, bool), ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        if source.is_empty() || source.len() > MAX_MESSAGE {
            return Err(ExtractError::Unsupported(
                "not an SNMPv3 capture or message".to_owned(),
            ));
        }
        let data = source.read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        if let Some(message) = parse_message(&data, "1") {
            return Ok((vec![message], true));
        }
        return match snmp_version(&data) {
            Some(_) => Ok((Vec::new(), true)),
            None => Err(ExtractError::Unsupported(
                "not an SNMPv3 message".to_owned(),
            )),
        };
    }

    let mut messages = Vec::new();
    let mut seen = false;
    capture::scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Udp {
            return;
        }
        if !SNMP_PORTS.contains(&datagram.source.port())
            && !SNMP_PORTS.contains(&datagram.destination.port())
        {
            return;
        }
        if snmp_version(datagram.payload).is_some() {
            seen = true;
        }
        if let Some(message) = parse_message(datagram.payload, &datagram.index.to_string()) {
            messages.push(message);
        }
    })?;
    Ok((messages, seen))
}

impl Extractor for Snmpv3Extractor {
    fn slug(&self) -> &'static str {
        Snmpv3::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok((messages, _)) if !messages.is_empty() => {
                Probe::yes("SNMPv3 USM authenticated message")
            }
            Ok((_, true)) => Probe::Maybe("SNMP message without USM authentication".to_owned()),
            Ok((_, false)) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let (messages, _) = scan(artifact)?;
        if messages.is_empty() {
            return Err(ExtractError::Unsupported(
                "no authenticated SNMPv3 messages".to_owned(),
            ));
        }
        let unique: BTreeSet<_> = messages
            .into_iter()
            .map(|message| {
                (
                    message.submode,
                    message.packet_number,
                    message.message,
                    message.engine_id,
                    message.digest,
                )
            })
            .collect();
        Ok(unique
            .into_iter()
            .map(|(version, packet_number, message, engine_id, digest)| {
                Box::new(Snmpv3 {
                    version,
                    packet_number,
                    message,
                    engine_id,
                    digest,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
