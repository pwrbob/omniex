//! Kerberos 4 KDC reply extraction.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::extract::wpa_pmkid::net;
use crate::types::Krb4;
use crate::{HashType, HashValue};

const KDC_REPLY: u8 = 2 << 1;
const TGT_LENGTH: usize = 16;

fn truncated() -> ExtractError {
    ExtractError::Invalid("truncated Kerberos 4 KDC reply".to_owned())
}

fn c_string(data: &[u8], offset: &mut usize, limit: usize) -> Result<String, ExtractError> {
    let rest = data.get(*offset..).ok_or_else(truncated)?;
    let length = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| ExtractError::Invalid("unterminated Kerberos 4 string".to_owned()))?;
    if length > limit {
        return Err(ExtractError::Invalid(
            "Kerberos 4 string is too long".to_owned(),
        ));
    }
    let value = String::from_utf8_lossy(&rest[..length]).into_owned();
    *offset += length + 1;
    Ok(value)
}

fn reply(data: &[u8]) -> Result<Option<(String, [u8; TGT_LENGTH])>, ExtractError> {
    if data.len() < 2 {
        return Err(truncated());
    }
    if data[0] != 4 || data[1] & 0xfe != KDC_REPLY {
        return Ok(None);
    }
    let little_endian = data[1] & 1 != 0;
    let mut offset = 2;
    let _name = c_string(data, &mut offset, 64)?;
    let _instance = c_string(data, &mut offset, 64)?;
    let realm = c_string(data, &mut offset, 64)?;
    if realm.is_empty() {
        return Err(ExtractError::Invalid(
            "Kerberos 4 KDC reply has an empty realm".to_owned(),
        ));
    }
    offset = offset.checked_add(9).ok_or_else(truncated)?;
    let length_bytes = data.get(offset..offset + 2).ok_or_else(truncated)?;
    let length = if little_endian {
        usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]))
    } else {
        usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]))
    };
    offset += 2;
    if length < TGT_LENGTH || length % 8 != 0 {
        return Err(ExtractError::Invalid(
            "Kerberos 4 reply ciphertext has an invalid length".to_owned(),
        ));
    }
    let cipher = data.get(offset..offset + length).ok_or_else(truncated)?;
    let tgt = cipher
        .get(..TGT_LENGTH)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(truncated)?;
    Ok(Some((realm, tgt)))
}

fn values(artifact: &Artifact) -> Result<Vec<Krb4>, ExtractError> {
    let source = artifact.primary();
    let mut records = BTreeSet::new();
    if net::is_capture(source) {
        let mut failure = None;
        net::scan(source, |link_type, frame| {
            if failure.is_some() {
                return;
            }
            let Some(payload) = net::kerberos_payload(link_type, frame) else {
                return;
            };
            match reply(payload) {
                Ok(Some((realm, tgt))) => {
                    records.insert((realm, tgt));
                }
                Ok(None) => {}
                Err(error) => failure = Some(error),
            }
        })?;
        if let Some(error) = failure {
            return Err(error);
        }
    } else {
        let data = source
            .read_all()
            .map_err(|error| ExtractError::Invalid(format!("cannot read artifact: {error}")))?;
        match reply(&data)? {
            Some((realm, tgt)) => {
                records.insert((realm, tgt));
            }
            None => {
                return Err(ExtractError::Unsupported(
                    "not a Kerberos 4 KDC reply".to_owned(),
                ));
            }
        }
    }
    Ok(records
        .into_iter()
        .map(|(realm, tgt)| Krb4 {
            realm,
            data: crate::format::hex(tgt),
        })
        .collect())
}

pub struct Krb4Extractor;

impl Extractor for Krb4Extractor {
    fn slug(&self) -> &'static str {
        Krb4::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if artifact.primary().is_empty() {
            return Probe::No;
        }
        match values(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("Kerberos 4 KDC reply"),
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos 4 KDC replies".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
