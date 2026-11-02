//! Cardano legacy secret key (`secret.key`) extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::CardanoJohn;
use crate::{HashType, HashValue};

pub struct CardanoExtractor;

enum Cbor {
    Bytes(Vec<u8>),
    Array(Vec<Cbor>),
    Other,
}

fn length(data: &[u8], additional: u8) -> Result<(usize, &[u8]), ExtractError> {
    let (value, rest) = match additional {
        0..=23 => (u64::from(additional), data),
        24 => {
            let value = *data
                .first()
                .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
            (u64::from(value), &data[1..])
        }
        25 => {
            let bytes = data
                .get(..2)
                .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
            (
                u64::from(u16::from_be_bytes([bytes[0], bytes[1]])),
                &data[2..],
            )
        }
        26 => {
            let bytes = data
                .get(..4)
                .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
            (
                u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                &data[4..],
            )
        }
        27 => {
            let bytes = data
                .get(..8)
                .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
            (
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                &data[8..],
            )
        }
        _ => {
            return Err(ExtractError::Invalid(
                "unsupported Cardano CBOR length".to_owned(),
            ));
        }
    };
    let value = usize::try_from(value)
        .map_err(|_| ExtractError::Invalid("Cardano CBOR length is too large".to_owned()))?;
    Ok((value, rest))
}

fn value(data: &[u8]) -> Result<(Cbor, &[u8]), ExtractError> {
    let (&initial, rest) = data
        .split_first()
        .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    match major {
        0 | 1 => {
            let (_, rest) = length(rest, additional)?;
            Ok((Cbor::Other, rest))
        }
        2 | 3 => {
            let (length, rest) = length(rest, additional)?;
            let bytes = rest
                .get(..length)
                .ok_or_else(|| ExtractError::Invalid("truncated Cardano CBOR".to_owned()))?;
            Ok((Cbor::Bytes(bytes.to_vec()), &rest[length..]))
        }
        4 => {
            let (count, mut rest) = length(rest, additional)?;
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let (item, next) = value(rest)?;
                items.push(item);
                rest = next;
            }
            Ok((Cbor::Array(items), rest))
        }
        5 => {
            let (count, mut rest) = length(rest, additional)?;
            let pairs = count
                .checked_mul(2)
                .ok_or_else(|| ExtractError::Invalid("Cardano CBOR map is too large".to_owned()))?;
            for _ in 0..pairs {
                let (_, next) = value(rest)?;
                rest = next;
            }
            Ok((Cbor::Other, rest))
        }
        6 => {
            let (_, rest) = length(rest, additional)?;
            value(rest)
        }
        7 => {
            let (_, rest) = length(rest, additional)?;
            Ok((Cbor::Other, rest))
        }
        _ => unreachable!(),
    }
}

fn parse(artifact: &Artifact) -> Result<Vec<CardanoJohn>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let (root, rest) = value(&data)?;
    if !rest.is_empty() {
        return Err(ExtractError::Invalid(
            "trailing Cardano CBOR data".to_owned(),
        ));
    }
    let Cbor::Array(items) = root else {
        return Err(ExtractError::Unsupported(
            "not a Cardano secret key".to_owned(),
        ));
    };
    if items.len() < 4 {
        return Err(ExtractError::Unsupported(
            "not a Cardano secret key".to_owned(),
        ));
    }
    let mut hashes = Vec::new();
    for item in [&items[2], &items[3]] {
        let Cbor::Array(keys) = item else {
            continue;
        };
        for key in keys {
            let Cbor::Array(key) = key else {
                continue;
            };
            let Some(Cbor::Bytes(esk)) = key.first() else {
                continue;
            };
            hashes.push(CardanoJohn {
                fields: format!("1${}", crate::format::hex(esk)),
            });
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Cardano keys found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for CardanoExtractor {
    fn slug(&self) -> &'static str {
        CardanoJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Cardano secret key"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
