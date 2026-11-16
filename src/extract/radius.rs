//! RADIUS PAP exchange extraction.
//!
//! The RADIUS hash type attacks the encrypted `User-Password` attribute, so
//! either the shared secret or the user password must come from a sidecar. A
//! `.salt` sidecar is treated as the shared secret, allowing the recovered
//! value to be the user password.

use std::collections::BTreeSet;

use super::iscsi_chap::capture::{self, Protocol};
use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe};
use crate::types::Radius;
use crate::{HashType, HashValue};

const AUTH_PORTS: [u16; 2] = [1812, 1645];
const ACCESS_REQUEST: u8 = 1;
const USER_PASSWORD: u8 = 2;

/// Extracts RADIUS PAP exchanges from a packet capture.
pub struct RadiusExtractor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Record {
    authenticator: [u8; 16],
    ciphertext: [u8; 16],
}

fn attributes(data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut result = Vec::new();
    let mut offset = 20;
    while offset < data.len() {
        let kind = *data.get(offset)?;
        let length = usize::from(*data.get(offset + 1)?);
        if length < 2 || offset + length > data.len() {
            return None;
        }
        result.push((kind, &data[offset + 2..offset + length]));
        offset += length;
    }
    Some(result)
}

fn looks_like_radius(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    length == data.len() && matches!(data[0], 1..=5 | 11)
}

fn records(artifact: &Artifact) -> Result<(Vec<Record>, bool), ExtractError> {
    let source = artifact.primary();
    if !capture::is_capture(source) {
        return Err(ExtractError::Unsupported(
            "not a RADIUS packet capture".to_owned(),
        ));
    }
    let mut records = Vec::new();
    let mut seen = false;
    capture::scan_datagrams(source, |datagram| {
        if datagram.protocol != Protocol::Udp
            || !AUTH_PORTS.contains(&datagram.source.port())
                && !AUTH_PORTS.contains(&datagram.destination.port())
        {
            return;
        }
        let data = datagram.payload;
        if !looks_like_radius(data) {
            return;
        }
        seen = true;
        if data[0] != ACCESS_REQUEST {
            return;
        }
        let Some(fields) = attributes(data) else {
            return;
        };
        let authenticator: [u8; 16] = match data.get(4..20).and_then(|value| value.try_into().ok())
        {
            Some(value) => value,
            None => return,
        };
        for (kind, value) in fields {
            if kind != USER_PASSWORD || value.len() < 16 || value.len() % 16 != 0 {
                continue;
            }
            if let Ok(ciphertext) = <[u8; 16]>::try_from(&value[..16]) {
                records.push(Record {
                    authenticator,
                    ciphertext,
                });
            }
        }
    })?;
    Ok((records, seen))
}

fn parameter(artifact: &Artifact) -> Result<(u8, String), ExtractError> {
    let (name, mode) = if artifact.member("radius-password").is_some() {
        ("radius-password", 0)
    } else if artifact.member("radius-secret").is_some() {
        ("radius-secret", 1)
    } else if artifact.member("salt").is_some() {
        ("salt", 1)
    } else {
        return Err(ExtractError::Unsupported(
            "RADIUS extraction needs the shared secret or user password in a sidecar".to_owned(),
        ));
    };
    let mut bytes = data(artifact, name)?;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(ExtractError::Invalid(format!(
            "RADIUS {name} sidecar is empty or contains a NUL byte"
        )));
    }
    let secret = String::from_utf8(bytes)
        .map_err(|_| ExtractError::Invalid(format!("RADIUS {name} sidecar is not UTF-8")))?;
    Ok((mode, secret))
}

fn data(artifact: &Artifact, name: &str) -> Result<Vec<u8>, ExtractError> {
    let member = artifact
        .member(name)
        .ok_or_else(|| ExtractError::Unsupported(format!("missing RADIUS {name} sidecar")))?;
    member.read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read RADIUS {name} sidecar: {error}"))
    })
}

const COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional(
        "radius-password",
        "user password; one of the three sidecars is required",
    ),
    CompanionSpec::optional(
        "radius-secret",
        "shared secret; one of the three sidecars is required",
    ),
    CompanionSpec::optional(
        "salt",
        "shared secret; one of the three sidecars is required",
    ),
];

impl Extractor for RadiusExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        Radius::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match records(artifact) {
            Ok((records, _)) if !records.is_empty() => match parameter(artifact) {
                Ok(_) => Probe::yes("RADIUS User-Password attribute"),
                Err(ExtractError::Unsupported(reason)) => Probe::maybe(reason),
                Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
            },
            Ok((_, true)) => {
                Probe::Maybe("RADIUS exchange without a User-Password attribute".to_owned())
            }
            Ok((_, false)) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let (records, _) = records(artifact)?;
        if records.is_empty() {
            return Err(ExtractError::Unsupported(
                "no RADIUS User-Password attributes".to_owned(),
            ));
        }
        let (mode, secret) = parameter(artifact)?;
        let unique: BTreeSet<Record> = records.into_iter().collect();
        Ok(unique
            .into_iter()
            .map(|record| {
                Box::new(Radius {
                    version: 1,
                    kind: mode,
                    secret: secret.clone(),
                    digest: record.authenticator,
                    data: record.ciphertext,
                }) as Box<dyn HashValue>
            })
            .collect())
    }
}
