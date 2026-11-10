//! POP3 APOP challenge-response extraction from packet captures.
//!
//! The server greeting supplies the shared challenge and the `APOP` command
//! supplies the MD5 digest over that challenge and the user's password.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::str;

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pop3Apop;
use crate::{HashType, HashValue};

const POP3_PORT: u16 = 110;
const MAX_STREAM: usize = 1024 * 1024;

/// Extracts POP3 APOP exchanges from a packet capture.
pub struct Pop3ApopExtractor;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Record {
    challenge: String,
    digest: [u8; 16],
}

#[derive(Default)]
struct Connection {
    client: Vec<u8>,
    server: Vec<u8>,
    challenge: Option<String>,
    records: Vec<Record>,
    apop_seen: bool,
    pop3_seen: bool,
}

#[derive(Default)]
struct Parsed {
    connections: BTreeMap<(SocketAddr, SocketAddr), Connection>,
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_digest(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(out)
}

fn challenge(text: &str) -> Option<String> {
    let start = text.find('<')?;
    let end = text[start..].find('>')? + start;
    Some(text[start..=end].to_owned())
}

fn server_line(connection: &mut Connection, line: &[u8]) {
    let Ok(line) = str::from_utf8(line) else {
        return;
    };
    if !line
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("+ok"))
    {
        return;
    }
    connection.pop3_seen = true;
    if let Some(challenge) = challenge(line) {
        connection.challenge = Some(challenge);
    }
}

fn client_line(connection: &mut Connection, line: &[u8]) {
    let Ok(line) = str::from_utf8(line) else {
        return;
    };
    let Some(rest) = line
        .get(..5)
        .filter(|prefix| prefix.eq_ignore_ascii_case("APOP "))
        .map(|_| &line[5..])
    else {
        return;
    };
    connection.pop3_seen = true;
    let mut parts = rest.split_ascii_whitespace();
    let (Some(_user), Some(digest)) = (parts.next(), parts.next()) else {
        return;
    };
    let Some(digest) = decode_digest(digest) else {
        return;
    };
    connection.apop_seen = true;
    let Some(challenge) = connection.challenge.clone() else {
        return;
    };
    connection.records.push(Record { challenge, digest });
}

fn drain_lines(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    while let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
        let mut line = buffer[..position].to_vec();
        buffer.drain(..=position);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        lines.push(line);
    }
    if buffer.len() > MAX_STREAM {
        buffer.clear();
    }
    lines
}

fn scan(artifact: &Artifact) -> Result<Parsed, ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not a POP3 packet capture".to_owned(),
        ));
    }
    let mut parsed = Parsed::default();
    capture::scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Tcp {
            return;
        }
        let from_server = datagram.source.port() == POP3_PORT;
        let (client, server) = if datagram.destination.port() == POP3_PORT {
            (datagram.source, datagram.destination)
        } else if from_server {
            (datagram.destination, datagram.source)
        } else {
            return;
        };
        let connection = parsed.connections.entry((client, server)).or_default();
        if from_server {
            connection.server.extend_from_slice(datagram.payload);
            for line in drain_lines(&mut connection.server) {
                server_line(connection, &line);
            }
        } else {
            connection.client.extend_from_slice(datagram.payload);
            for line in drain_lines(&mut connection.client) {
                client_line(connection, &line);
            }
        }
    })?;
    Ok(parsed)
}

fn is_empty(parsed: &Parsed) -> bool {
    parsed
        .connections
        .values()
        .all(|connection| connection.records.is_empty())
}

impl Extractor for Pop3ApopExtractor {
    fn slug(&self) -> &'static str {
        Pop3Apop::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok(parsed) if !is_empty(&parsed) => Probe::yes("POP3 APOP challenge and response"),
            Ok(parsed)
                if parsed
                    .connections
                    .values()
                    .any(|connection| connection.apop_seen) =>
            {
                Probe::maybe("POP3 APOP command without a preceding challenge")
            }
            Ok(parsed)
                if parsed
                    .connections
                    .values()
                    .any(|connection| connection.pop3_seen) =>
            {
                Probe::maybe("POP3 traffic without an APOP exchange")
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let parsed = scan(artifact)?;
        if is_empty(&parsed) {
            return Err(ExtractError::Unsupported(
                "no POP3 APOP challenge-response exchange".to_owned(),
            ));
        }
        let records: BTreeSet<Record> = parsed
            .connections
            .into_values()
            .flat_map(|connection| connection.records)
            .collect();
        Ok(records
            .into_iter()
            .map(|record| {
                Box::new(Pop3Apop {
                    challenge: record.challenge,
                    digest: record.digest,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
