//! Oracle O5LOGON authentication extraction from TNS packet captures.
//!
//! The server's `AUTH_SESSKEY` and `AUTH_VFR_DATA` identify the session, while
//! the client's `AUTH_PASSWORD` and `AUTH_SESSKEY` provide the newer four-field
//! serialization.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::O5logon;
use crate::{HashType, HashValue};

const MIN_TNS_PACKET: usize = 8;
const MAX_STREAM: usize = 1024 * 1024;

/// Extracts Oracle O5LOGON exchanges from a packet capture.
pub struct O5logonExtractor;

#[derive(Default)]
struct Stream {
    buffer: Vec<u8>,
    tns: bool,
    decided: bool,
    invalid: Option<String>,
}

#[derive(Default, Clone)]
struct Exchange {
    server_key: Option<String>,
    vfr_data: Option<String>,
    password: Option<String>,
    client_key: Option<String>,
}

impl Exchange {
    fn complete(&self) -> bool {
        self.server_key.is_some() && self.vfr_data.is_some()
    }
}

#[derive(Default)]
struct Connection {
    streams: [Stream; 2],
    exchanges: Vec<Exchange>,
}

#[derive(Default)]
struct Parsed {
    connections: BTreeMap<(SocketAddr, SocketAddr), Connection>,
    fields_seen: usize,
}

fn valid_tns_type(kind: u8) -> bool {
    matches!(kind, 1..=9 | 11..=19)
}

fn find_key(data: &[u8], from: usize) -> Option<(usize, &'static str)> {
    const KEYS: [&str; 3] = ["AUTH_SESSKEY", "AUTH_VFR_DATA", "AUTH_PASSWORD"];
    let rest = data.get(from..)?;
    KEYS.iter()
        .filter_map(|name| {
            rest.windows(name.len())
                .position(|window| window == name.as_bytes())
                .map(|position| (from + position, *name))
        })
        .min_by_key(|(position, _)| *position)
}

fn first_hex_run(value: &[u8]) -> Option<Vec<u8>> {
    let compact: Vec<u8> = value.iter().copied().filter(|byte| *byte != b' ').collect();
    let start = compact.iter().position(u8::is_ascii_hexdigit)?;
    let length = compact[start..]
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    let run = &compact[start..start + length];
    (run.len() >= 8 && run.len() % 2 == 0).then(|| run.to_vec())
}

fn key_values(data: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut values = Vec::new();
    let mut offset = 0usize;
    while let Some((position, name)) = find_key(data, offset) {
        let start = position + name.len();
        let end = find_key(data, start).map_or(data.len(), |(next, _)| next);
        if let Some(value) = first_hex_run(&data[start..end]) {
            values.push((name, value));
        }
        offset = end.max(start);
    }
    values
}

fn hex_text(value: &[u8]) -> Option<String> {
    if value.is_empty() || value.len() % 2 != 0 || !value.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::str::from_utf8(value).ok().map(str::to_owned)
}

fn current_exchange(exchanges: &mut Vec<Exchange>) -> &mut Exchange {
    if exchanges.is_empty() {
        exchanges.push(Exchange::default());
    }
    exchanges.last_mut().expect("exchange was just pushed")
}

fn apply_keys(exchanges: &mut Vec<Exchange>, values: &[(&str, Vec<u8>)]) -> Option<()> {
    let mut session_key = None;
    let mut vfr_data = None;
    let mut password = None;
    for (name, value) in values {
        match *name {
            "AUTH_SESSKEY" if session_key.is_none() => session_key = hex_text(value),
            "AUTH_VFR_DATA" if vfr_data.is_none() => vfr_data = hex_text(value),
            "AUTH_PASSWORD" if password.is_none() => password = hex_text(value),
            _ => {}
        }
    }
    let session_key = session_key?;
    if vfr_data.is_some() && password.is_some() {
        return None;
    }
    if let Some(vfr_data) = vfr_data {
        if exchanges
            .last()
            .is_some_and(|exchange| exchange.server_key.is_some())
        {
            exchanges.push(Exchange::default());
        }
        let exchange = current_exchange(exchanges);
        exchange.server_key = Some(session_key);
        exchange.vfr_data = Some(vfr_data);
    } else if let Some(password) = password {
        let exchange = current_exchange(exchanges);
        exchange.client_key = Some(session_key);
        exchange.password = Some(password);
    }
    Some(())
}

fn drain(stream: &mut Stream, exchanges: &mut Vec<Exchange>, fields_seen: &mut usize) {
    while stream.buffer.len() >= MIN_TNS_PACKET {
        let length = usize::from(u16::from_be_bytes([stream.buffer[0], stream.buffer[1]]));
        if length < MIN_TNS_PACKET {
            stream.invalid = Some("invalid Oracle TNS packet length".to_owned());
            stream.buffer.clear();
            return;
        }
        if stream.buffer.len() < length {
            break;
        }
        let packet: Vec<u8> = stream.buffer.drain(..length).collect();
        stream.tns = true;
        if packet[4] == 6 {
            let values = key_values(&packet[MIN_TNS_PACKET..]);
            if !values.is_empty() {
                *fields_seen += 1;
                let has_session_key = values.iter().any(|(name, _)| *name == "AUTH_SESSKEY");
                if apply_keys(exchanges, &values).is_none() && has_session_key {
                    stream.invalid = Some("invalid Oracle TNS authentication fields".to_owned());
                }
            }
        }
    }
    if stream.buffer.len() > MAX_STREAM {
        stream.invalid = Some("Oracle TNS stream is too large".to_owned());
        stream.buffer.clear();
    }
}

fn classify(stream: &mut Stream) -> bool {
    if stream.decided {
        return stream.tns;
    }
    if stream.buffer.len() < MIN_TNS_PACKET {
        return false;
    }
    let length = usize::from(u16::from_be_bytes([stream.buffer[0], stream.buffer[1]]));
    let kind = stream.buffer[4];
    stream.decided = true;
    stream.tns = length >= MIN_TNS_PACKET && stream.buffer[5] == 0 && valid_tns_type(kind);
    stream.tns
}

fn scan(artifact: &Artifact) -> Result<Parsed, ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not an Oracle TNS packet capture".to_owned(),
        ));
    }
    let mut parsed = Parsed::default();
    capture::scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Tcp || datagram.payload.is_empty() {
            return;
        }
        let first_is_forward = datagram.source < datagram.destination;
        let endpoints = if first_is_forward {
            (datagram.source, datagram.destination)
        } else {
            (datagram.destination, datagram.source)
        };
        let connection = parsed.connections.entry(endpoints).or_default();
        let index = usize::from(!first_is_forward);
        let stream = &mut connection.streams[index];
        stream.buffer.extend_from_slice(datagram.payload);
        let is_tns = classify(stream);
        if !is_tns && stream.decided {
            stream.buffer.clear();
        }
        if is_tns {
            let mut fields = parsed.fields_seen;
            let Connection {
                streams, exchanges, ..
            } = connection;
            drain(&mut streams[index], exchanges, &mut fields);
            parsed.fields_seen = fields;
        }
    })?;
    for connection in parsed.connections.values() {
        for stream in &connection.streams {
            if stream.tns && !stream.buffer.is_empty() && stream.invalid.is_none() {
                return Err(ExtractError::Invalid(
                    "truncated Oracle TNS packet capture".to_owned(),
                ));
            }
            if let Some(reason) = &stream.invalid {
                return Err(ExtractError::Invalid(reason.clone()));
            }
        }
    }
    Ok(parsed)
}

fn has_exchange(parsed: &Parsed) -> bool {
    parsed
        .connections
        .values()
        .any(|connection| connection.exchanges.iter().any(Exchange::complete))
}

impl Extractor for O5logonExtractor {
    fn slug(&self) -> &'static str {
        O5logon::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok(parsed) if has_exchange(&parsed) => {
                Probe::yes("Oracle O5LOGON TNS AUTH_SESSKEY and AUTH_VFR_DATA exchange")
            }
            Ok(parsed) if parsed.fields_seen > 0 => {
                Probe::maybe("Oracle TNS authentication data without a complete O5LOGON exchange")
            }
            Ok(parsed)
                if parsed
                    .connections
                    .values()
                    .any(|connection| connection.streams.iter().any(|stream| stream.tns)) =>
            {
                Probe::maybe("Oracle TNS traffic without O5LOGON authentication data")
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let parsed = scan(artifact)?;
        let mut hashes: Vec<Box<dyn HashValue>> = Vec::new();
        for connection in parsed.connections.into_values() {
            for exchange in connection.exchanges {
                let Some(server_key) = exchange.server_key else {
                    continue;
                };
                let Some(vfr_data) = exchange.vfr_data else {
                    continue;
                };
                let digest = match (exchange.password, exchange.client_key) {
                    (Some(password), Some(client_key)) => {
                        format!("{vfr_data}*{password}*{client_key}")
                    }
                    _ => vfr_data,
                };
                hashes.push(Box::new(O5logon {
                    data: server_key,
                    digest,
                }));
            }
        }
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Oracle O5LOGON authentication exchange".to_owned(),
            ));
        }
        Ok(hashes)
    }
}
