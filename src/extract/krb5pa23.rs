//! Kerberos 5 etype 23 AS-REQ pre-authentication extraction.
//!
//! The DER reader lives in [`asreq`] so the etype 17 and 18 extractors share
//! one AS-REQ parser.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5pa23;
use crate::{HashType, HashValue};

pub(crate) mod asreq {
    //! Minimal Kerberos 5 DER decoder for AS-REQ pre-authentication messages.

    use crate::extract::{Artifact, ExtractError, Probe, ReadAt, wpa_pmkid::net};

    const AS_REQ: u8 = 0x6a;
    const MAX_RAW_MESSAGE: u64 = 1024 * 1024;
    const PA_ENC_TIMESTAMP: i64 = 2;
    const AS_REQ_MSG_TYPE: i64 = 10;

    #[derive(Debug, Clone)]
    pub(crate) struct Message {
        pub(crate) etype: i32,
        pub(crate) realm: String,
        pub(crate) username: String,
        pub(crate) cipher: Vec<u8>,
    }

    fn tlv(data: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
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
        Some((tag, &data[body..body + length], body + length))
    }

    fn fields(content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
        let mut result = Vec::new();
        let mut offset = 0;
        while offset < content.len() {
            let (tag, value, next) = tlv(content, offset)?;
            result.push((tag, value));
            offset = next;
        }
        Some(result)
    }

    fn single(value: &[u8], expected: u8) -> Option<&[u8]> {
        let (tag, inner, _) = tlv(value, 0)?;
        (tag == expected).then_some(inner)
    }

    fn integer(content: &[u8]) -> Option<i64> {
        if content.is_empty() || content.len() > 8 {
            return None;
        }
        let mut value = if content[0] & 0x80 != 0 { -1i64 } else { 0 };
        for byte in content {
            value = (value << 8) | i64::from(*byte);
        }
        Some(value)
    }

    fn string(value: &[u8]) -> Option<String> {
        let content = single(value, 0x1b)?;
        Some(String::from_utf8_lossy(content).into_owned())
    }

    fn principal(content: &[u8]) -> Option<String> {
        let mut components = Vec::new();
        for (tag, value) in fields(content)? {
            if tag != 0xa1 {
                continue;
            }
            let names = single(value, 0x30)?;
            for (name_tag, name) in fields(names)? {
                if name_tag == 0x1b {
                    components.push(String::from_utf8_lossy(name).into_owned());
                }
            }
        }
        (!components.is_empty()).then(|| components.join("/"))
    }

    fn encrypted(value: &[u8]) -> Option<(i32, Vec<u8>)> {
        let content = single(value, 0x30)?;
        let mut etype = None;
        let mut cipher = None;
        for (tag, field) in fields(content)? {
            match tag {
                0xa0 => etype = Some(integer(single(field, 0x02)?)?),
                0xa2 => cipher = Some(single(field, 0x04)?.to_vec()),
                _ => {}
            }
        }
        Some((i32::try_from(etype?).ok()?, cipher?))
    }

    fn pre_auth(value: &[u8]) -> Option<(i32, Vec<u8>)> {
        let entries = single(value, 0x30)?;
        for (tag, entry) in fields(entries)? {
            if tag != 0x30 {
                continue;
            }
            let mut kind = None;
            let mut data = None;
            for (field_tag, field) in fields(entry)? {
                match field_tag {
                    0xa1 => kind = Some(integer(single(field, 0x02)?)?),
                    0xa2 => data = Some(field),
                    _ => {}
                }
            }
            if kind != Some(PA_ENC_TIMESTAMP) {
                continue;
            }
            return encrypted(data?);
        }
        None
    }

    fn request_body(content: &[u8]) -> Option<(String, String)> {
        let mut realm = None;
        let mut username = None;
        for (tag, value) in fields(content)? {
            match tag {
                0xa1 => username = principal(single(value, 0x30)?),
                0xa2 => realm = string(value),
                _ => {}
            }
        }
        Some((username?, realm?))
    }

    pub(crate) fn parse_message(data: &[u8]) -> Option<Message> {
        let (tag, content, _) = tlv(data, 0)?;
        if tag != AS_REQ {
            return None;
        }
        let content = single(content, 0x30)?;
        let mut message_type = None;
        let mut auth = None;
        let mut body = None;
        for (field, value) in fields(content)? {
            match field {
                0xa2 => message_type = Some(integer(single(value, 0x02)?)?),
                0xa3 => auth = Some(pre_auth(value)?),
                0xa4 => body = Some(request_body(single(value, 0x30)?)?),
                _ => {}
            }
        }
        if message_type? != AS_REQ_MSG_TYPE {
            return None;
        }
        let (username, realm) = body?;
        if username.is_empty() || realm.is_empty() {
            return None;
        }
        let (etype, cipher) = auth?;
        Some(Message {
            etype,
            realm,
            username,
            cipher,
        })
    }

    fn raw_message(source: &dyn ReadAt) -> Option<Message> {
        let length = source.len();
        if !(2..=MAX_RAW_MESSAGE).contains(&length) {
            return None;
        }
        let mut header = [0u8; 1];
        source.read_exact_at(0, &mut header).ok()?;
        if header[0] != AS_REQ {
            return None;
        }
        let data = source.read_all().ok()?;
        parse_message(&data)
    }

    /// Decodes every Kerberos AS-REQ pre-authentication message in the artifact.
    pub(crate) fn messages(artifact: &Artifact) -> Result<Vec<Message>, ExtractError> {
        let source = artifact.primary();
        if let Some(message) = raw_message(source) {
            return Ok(vec![message]);
        }
        if !net::is_capture(source) {
            return Err(ExtractError::Unsupported(
                "not a Kerberos capture".to_owned(),
            ));
        }
        let mut messages = Vec::new();
        net::scan(source, |link_type, frame| {
            if let Some(payload) = net::kerberos_payload(link_type, frame) {
                if let Some(message) = parse_message(payload) {
                    messages.push(message);
                }
            }
        })?;
        Ok(messages)
    }

    fn usable(message: &Message, etype: i32) -> bool {
        if message.etype != etype {
            return false;
        }
        if etype == 23 {
            message.cipher.len() == 52
        } else {
            matches!(etype, 17 | 18) && message.cipher.len() > 12
        }
    }

    /// Probes for an AS-REQ pre-authentication message of the given etype.
    pub(crate) fn probe_artifact(artifact: &Artifact, etype: i32) -> Probe {
        match messages(artifact) {
            Ok(messages) => {
                if messages.iter().any(|message| usable(message, etype)) {
                    Probe::yes(match etype {
                        23 => "Kerberos AS-REQ etype 23 pre-authentication",
                        17 => "Kerberos AS-REQ etype 17 pre-authentication",
                        18 => "Kerberos AS-REQ etype 18 pre-authentication",
                        _ => "Kerberos AS-REQ pre-authentication",
                    })
                } else {
                    Probe::No
                }
            }
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }
}

pub struct Krb5Pa23Extractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5pa23>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in asreq::messages(artifact)? {
        if message.etype != 23 || message.cipher.len() != 52 {
            continue;
        }
        let checksum = crate::format::hex(&message.cipher[..16]);
        let timestamp = crate::format::hex(&message.cipher[16..]);
        records.insert((message.username, message.realm, timestamp, checksum));
    }
    Ok(records
        .into_iter()
        .map(|(username, realm, timestamp, checksum)| Krb5pa23 {
            username,
            realm,
            salt: String::new(),
            timestamp,
            checksum,
        })
        .collect())
}

impl Extractor for Krb5Pa23Extractor {
    fn slug(&self) -> &'static str {
        Krb5pa23::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        asreq::probe_artifact(artifact, 23)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos AS-REQ etype 23 pre-authentication messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
