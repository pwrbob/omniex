//! TACACS+ encrypted authentication response extraction.
//!
//! Only server responses that carry an encrypted body are usable: the header
//! supplies the session id and sequence number, and the body supplies the known
//! keystream prefix that hashcat and John check.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::TacacsPlus;
use crate::{HashType, HashValue};

const TACACS_PORT: u16 = 49;
const TACACS_VERSION_MAJOR: u8 = 0xc0;
const TACACS_AUTHEN: u8 = 1;
const TACACS_UNENCRYPTED: u8 = 0x01;
const MIN_BODY: usize = 6;
const MAX_STREAM: usize = 1024 * 1024;

/// One session id, encrypted body, and sequence triple.
type HashRecord = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Extracts TACACS+ exchanges from a packet capture.
pub struct TacacsPlusExtractor;

#[derive(Default)]
struct Direction {
    buffer: Vec<u8>,
}

fn scan(artifact: &Artifact) -> Result<(Vec<HashRecord>, bool), ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not a TACACS+ capture".to_owned(),
        ));
    }
    let mut directions: BTreeMap<(SocketAddr, SocketAddr), Direction> = BTreeMap::new();
    let mut records = Vec::new();
    let mut seen = false;
    capture::scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Tcp || datagram.source.port() != TACACS_PORT {
            return;
        }
        let direction = directions
            .entry((datagram.source, datagram.destination))
            .or_default();
        direction.buffer.extend_from_slice(datagram.payload);
        while direction.buffer.len() >= 12 {
            let length = u32::from_be_bytes([
                direction.buffer[8],
                direction.buffer[9],
                direction.buffer[10],
                direction.buffer[11],
            ]);
            let body_length = usize::try_from(length).unwrap_or(usize::MAX);
            let total = 12 + body_length;
            if body_length > MAX_STREAM || direction.buffer.len() < total {
                break;
            }
            let pdu = direction.buffer[..total].to_vec();
            direction.buffer.drain(..total);
            let version = pdu[0];
            if version & 0xf0 != TACACS_VERSION_MAJOR {
                continue;
            }
            seen = true;
            if pdu[1] != TACACS_AUTHEN || pdu[3] & TACACS_UNENCRYPTED != 0 {
                continue;
            }
            if body_length < MIN_BODY {
                continue;
            }
            records.push((
                pdu[4..8].to_vec(),
                pdu[12..].to_vec(),
                vec![TACACS_VERSION_MAJOR | (version & 0x0f), pdu[2]],
            ));
        }
        if direction.buffer.len() > MAX_STREAM {
            direction.buffer.clear();
        }
    })?;
    Ok((records, seen))
}

impl Extractor for TacacsPlusExtractor {
    fn slug(&self) -> &'static str {
        TacacsPlus::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact) {
            Ok((records, _)) if !records.is_empty() => {
                Probe::yes("TACACS+ encrypted authentication response")
            }
            Ok((_, true)) => Probe::Maybe(
                "TACACS+ capture without an encrypted authentication response".to_owned(),
            ),
            Ok((_, false)) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let (records, _) = scan(artifact)?;
        if records.is_empty() {
            return Err(ExtractError::Unsupported(
                "no TACACS+ encrypted authentication responses".to_owned(),
            ));
        }
        let unique: BTreeSet<_> = records.into_iter().collect();
        Ok(unique
            .into_iter()
            .map(|(salt, key, digest)| {
                Box::new(TacacsPlus {
                    version: 0,
                    salt,
                    key,
                    digest,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
