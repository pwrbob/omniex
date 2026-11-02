//! Bisq (bitcoinj) wallet extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Bisq;
use crate::{HashType, HashValue};

pub struct BisqExtractor;

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

fn fields(mut data: &[u8]) -> Result<Vec<(u64, Field<'_>)>, ExtractError> {
    let mut result = Vec::new();
    while !data.is_empty() {
        let (tag, rest) = varint(data)?;
        data = rest;
        let number = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                let (value, rest) = varint(data)?;
                data = rest;
                result.push((number, Field::Varint(value)));
            }
            1 => {
                data = data
                    .get(8..)
                    .ok_or_else(|| ExtractError::Invalid("truncated Bisq wallet".to_owned()))?;
                result.push((number, Field::Fixed));
            }
            2 => {
                let (length, rest) = varint(data)?;
                let length = usize::try_from(length)
                    .map_err(|_| ExtractError::Invalid("invalid Bisq field length".to_owned()))?;
                let value = rest.get(..length).ok_or_else(|| {
                    ExtractError::Invalid("truncated Bisq wallet field".to_owned())
                })?;
                data = &rest[length..];
                result.push((number, Field::Bytes(value)));
            }
            5 => {
                data = data
                    .get(4..)
                    .ok_or_else(|| ExtractError::Invalid("truncated Bisq wallet".to_owned()))?;
                result.push((number, Field::Fixed));
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "unsupported Bisq protobuf wire type".to_owned(),
                ));
            }
        }
    }
    Ok(result)
}

fn varint(data: &[u8]) -> Result<(u64, &[u8]), ExtractError> {
    let mut value = 0u64;
    for (index, byte) in data.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, &data[index + 1..]));
        }
    }
    Err(ExtractError::Invalid("invalid Bisq varint".to_owned()))
}

fn bytes<'a>(field: Option<&'a (u64, Field<'a>)>) -> Result<&'a [u8], ExtractError> {
    match field {
        Some((_, Field::Bytes(value))) => Ok(value),
        _ => Err(ExtractError::Invalid("missing Bisq field".to_owned())),
    }
}

fn number(field: Option<&(u64, Field<'_>)>) -> Result<u64, ExtractError> {
    match field {
        Some((_, Field::Varint(value))) => Ok(*value),
        _ => Err(ExtractError::Invalid("missing Bisq number".to_owned())),
    }
}

fn parse(artifact: &Artifact) -> Result<Vec<Bisq>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let wallet = fields(&data)?;
    let network = bytes(wallet.iter().find(|(number, _)| *number == 1))?;
    if !network.starts_with(b"org.bitcoin.") {
        return Err(ExtractError::Unsupported(
            "not a bitcoinj wallet".to_owned(),
        ));
    }
    if number(wallet.iter().find(|(number, _)| *number == 5))? != 1 {
        return Err(ExtractError::Unsupported(
            "wallet is not scrypt encrypted".to_owned(),
        ));
    }
    let params = fields(bytes(wallet.iter().find(|(number, _)| *number == 6))?)?;
    let salt: [u8; 8] = bytes(params.iter().find(|(number, _)| *number == 1))?
        .try_into()
        .map_err(|_| ExtractError::Invalid("Bisq salt must be 8 bytes".to_owned()))?;
    let n = u32::try_from(number(params.iter().find(|(number, _)| *number == 2))?)
        .map_err(|_| ExtractError::Invalid("Bisq n is too large".to_owned()))?;
    let r = u8::try_from(number(params.iter().find(|(number, _)| *number == 3))?)
        .map_err(|_| ExtractError::Invalid("Bisq r is too large".to_owned()))?;
    let p = u8::try_from(number(params.iter().find(|(number, _)| *number == 4))?)
        .map_err(|_| ExtractError::Invalid("Bisq p is too large".to_owned()))?;

    let mut hashes = Vec::new();
    for (number, field) in &wallet {
        if *number != 3 {
            continue;
        }
        let Field::Bytes(key) = field else {
            continue;
        };
        let key = fields(key)?;
        let Some((_, Field::Bytes(encrypted))) = key.iter().find(|(number, _)| *number == 6) else {
            continue;
        };
        let encrypted = fields(encrypted)?;
        let Some((_, Field::Bytes(encrypted_key))) =
            encrypted.iter().find(|(number, _)| *number == 1)
        else {
            continue;
        };
        if encrypted_key.len() != 48 {
            continue;
        }
        let digest: [u8; 32] = encrypted_key[16..]
            .try_into()
            .expect("48-byte key has a 32-byte tail");
        hashes.push(Bisq {
            version: 3,
            n,
            r,
            p,
            salt,
            digest,
        });
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no encrypted Bisq keys found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for BisqExtractor {
    fn slug(&self) -> &'static str {
        Bisq::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Bisq scrypt wallet"),
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
