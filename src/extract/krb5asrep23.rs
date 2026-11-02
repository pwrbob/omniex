//! Kerberos 5 etype 23 AS-REP extraction.
//!
//! The DER decoder and capture reader live in [`kerberos`] so the AES AS-REP
//! and the TGS-REP extractors share one message parser.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Krb5AsRep23;
use crate::{HashType, HashValue};

pub(crate) mod kerberos {
    //! Minimal Kerberos 5 DER decoder for AS-REP and TGS-REP messages.

    use crate::extract::{Artifact, ExtractError, Probe, ReadAt, wpa_pmkid::net};

    const AS_REP: u8 = 0x6b;
    const TGS_REP: u8 = 0x6d;
    const MAX_RAW_MESSAGE: u64 = 1024 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Kind {
        AsRep,
        TgsRep,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct Message {
        pub(crate) kind: Kind,
        pub(crate) etype: i32,
        pub(crate) realm: String,
        pub(crate) username: String,
        pub(crate) spn: Option<String>,
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

    struct Encrypted {
        etype: i32,
        cipher: Vec<u8>,
    }

    fn encrypted(content: &[u8]) -> Option<Encrypted> {
        let mut etype = None;
        let mut cipher = None;
        for (tag, value) in fields(content)? {
            match tag {
                0xa0 => etype = Some(integer(single(value, 0x02)?)?),
                0xa2 => cipher = Some(single(value, 0x04)?.to_vec()),
                _ => {}
            }
        }
        Some(Encrypted {
            etype: i32::try_from(etype?).ok()?,
            cipher: cipher?,
        })
    }

    fn ticket_spn(content: &[u8]) -> Option<String> {
        for (tag, value) in fields(content)? {
            if tag == 0xa2 {
                return principal(single(value, 0x30)?);
            }
        }
        None
    }

    pub(crate) fn parse_message(data: &[u8]) -> Option<Message> {
        let (tag, content, _) = tlv(data, 0)?;
        let kind = match tag {
            AS_REP => Kind::AsRep,
            TGS_REP => Kind::TgsRep,
            _ => return None,
        };
        let content = single(content, 0x30)?;
        let mut realm = None;
        let mut username = None;
        let mut spn = None;
        let mut enc = None;
        for (field, value) in fields(content)? {
            match field {
                0xa3 => realm = string(value),
                0xa4 => username = principal(single(value, 0x30)?),
                0xa5 if kind == Kind::TgsRep => spn = ticket_spn(single(value, 0x30)?),
                0xa6 => enc = encrypted(single(value, 0x30)?),
                _ => {}
            }
        }
        let enc = enc?;
        Some(Message {
            kind,
            etype: enc.etype,
            realm: realm?,
            username: username?,
            spn,
            cipher: enc.cipher,
        })
    }

    fn raw_message(source: &dyn ReadAt) -> Option<Message> {
        let length = source.len();
        if !(2..=MAX_RAW_MESSAGE).contains(&length) {
            return None;
        }
        let mut header = [0u8; 2];
        source.read_exact_at(0, &mut header).ok()?;
        if !matches!(header[0], AS_REP | TGS_REP) {
            return None;
        }
        let data = source.read_all().ok()?;
        parse_message(&data)
    }

    /// Decodes every Kerberos AS-REP and TGS-REP message in the artifact.
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

    /// Probes for the given message kind and encryption type.
    pub(crate) fn probe(artifact: &Artifact, kind: Kind, etype: i32) -> Result<bool, ExtractError> {
        Ok(messages(artifact)?.into_iter().any(|message| {
            let checksum = match etype {
                23 => 16,
                17 | 18 => 12,
                _ => 0,
            };
            message.kind == kind
                && message.etype == etype
                && message.cipher.len() > checksum
                && (kind != Kind::TgsRep
                    || message.spn.as_ref().is_some_and(|spn| !spn.is_empty()))
        }))
    }

    pub(crate) fn probe_artifact(artifact: &Artifact, kind: Kind, etype: i32) -> Probe {
        match probe(artifact, kind, etype) {
            Ok(true) => Probe::yes(match kind {
                Kind::AsRep => "Kerberos AS-REP message",
                Kind::TgsRep => "Kerberos TGS-REP message",
            }),
            Ok(false) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }
}

pub struct Krb5AsRep23Extractor;

fn values(artifact: &Artifact) -> Result<Vec<Krb5AsRep23>, ExtractError> {
    let mut records = BTreeSet::new();
    for message in kerberos::messages(artifact)? {
        if message.kind != kerberos::Kind::AsRep
            || message.etype != 23
            || message.cipher.len() <= 16
        {
            continue;
        }
        let checksum: [u8; 16] = message
            .cipher
            .get(..16)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ExtractError::Invalid("short Kerberos checksum".to_owned()))?;
        records.insert((
            message.username,
            message.realm,
            checksum,
            message.cipher[16..].to_vec(),
        ));
    }
    Ok(records
        .into_iter()
        .map(|(username, realm, checksum, ciphertext)| Krb5AsRep23 {
            username,
            realm,
            checksum,
            ciphertext,
        })
        .collect())
}

impl Extractor for Krb5AsRep23Extractor {
    fn slug(&self) -> &'static str {
        Krb5AsRep23::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        kerberos::probe_artifact(artifact, kerberos::Kind::AsRep, 23)
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Kerberos AS-REP etype 23 messages".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
