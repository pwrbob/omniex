//! SAP PSE PKCS#12 PBE extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Sappse;
use crate::{HashType, HashValue};

pub struct SappseExtractor;

const PBE_SHA1_3DES_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_ENCRYPTED_CONTENT_V2: u8 = 0xa0;
const TAG_ENCRYPTED_CONTENT_V4: u8 = 0xa3;

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn value(&mut self) -> Result<(u8, &'a [u8]), ExtractError> {
        let (tag, value, rest) = Tlv::read(self.data)?;
        self.data = rest;
        Ok((tag, value))
    }
}

struct Tlv;

impl Tlv {
    fn read(data: &[u8]) -> Result<(u8, &[u8], &[u8]), ExtractError> {
        let (&tag, rest) = data
            .split_first()
            .ok_or_else(|| ExtractError::Invalid("truncated SAP PSE DER value".to_owned()))?;
        let Some((&first, rest)) = rest.split_first() else {
            return Err(ExtractError::Invalid(
                "truncated SAP PSE DER length".to_owned(),
            ));
        };
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(ExtractError::Invalid(
                    "invalid SAP PSE DER length".to_owned(),
                ));
            }
            let mut length = 0usize;
            for byte in &rest[..count] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| {
                        ExtractError::Invalid("SAP PSE DER length is too large".to_owned())
                    })?;
            }
            (length, &rest[count..])
        };
        let (value, rest) = rest
            .split_at_checked(length)
            .ok_or_else(|| ExtractError::Invalid("truncated SAP PSE DER value".to_owned()))?;
        Ok((tag, value, rest))
    }
}

fn expect_tag<'a>(der: &mut Der<'a>, tag: u8, what: &str) -> Result<&'a [u8], ExtractError> {
    let (actual, value) = der.value()?;
    if actual != tag {
        return Err(ExtractError::Invalid(format!(
            "SAP PSE {what} has tag 0x{actual:02x}, expected 0x{tag:02x}"
        )));
    }
    Ok(value)
}

fn parse_integer(value: &[u8]) -> Result<u64, ExtractError> {
    if value.is_empty() || value.len() > 8 {
        return Err(ExtractError::Invalid("invalid SAP PSE integer".to_owned()));
    }
    let mut result = 0u64;
    for byte in value {
        result = result * 256 + u64::from(*byte);
    }
    Ok(result)
}

fn parse(artifact: &Artifact) -> Result<Sappse, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut root = Der::new(&data);
    let root = expect_tag(&mut root, TAG_SEQUENCE, "file")?;
    let mut file = Der::new(root);

    let version = parse_integer(expect_tag(&mut file, TAG_INTEGER, "version")?)?;
    let (content_tag, content) = file.value()?;
    if content_tag == TAG_ENCRYPTED_CONTENT_V4 {
        return Err(ExtractError::Unsupported(
            "SAP PSE v4 encryption is not supported".to_owned(),
        ));
    }
    if content_tag != TAG_ENCRYPTED_CONTENT_V2 {
        return Err(ExtractError::Unsupported(format!(
            "SAP PSE content tag 0x{content_tag:02x} is not an encrypted v2 container"
        )));
    }
    if version != 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported SAP PSE version {version}"
        )));
    }

    let mut encrypted = Der::new(content);
    let encrypted_pin = expect_tag(&mut encrypted, TAG_OCTET_STRING, "encrypted PIN")?;
    let algorithm = expect_tag(&mut encrypted, TAG_SEQUENCE, "algorithm identifier")?;
    let mut algorithm = Der::new(algorithm);
    let oid = expect_tag(&mut algorithm, TAG_OID, "algorithm OID")?;
    if oid != PBE_SHA1_3DES_OID {
        return Err(ExtractError::Unsupported(
            "unsupported SAP PSE encryption algorithm".to_owned(),
        ));
    }
    let parameters = expect_tag(&mut algorithm, TAG_SEQUENCE, "PBE parameters")?;
    let mut parameters = Der::new(parameters);
    let salt = expect_tag(&mut parameters, TAG_OCTET_STRING, "salt")?;
    let iterations = parse_integer(expect_tag(&mut parameters, TAG_INTEGER, "iteration count")?)?;

    let _ciphertext = expect_tag(&mut encrypted, TAG_OCTET_STRING, "ciphertext")?;

    if encrypted_pin.len() > 128 {
        return Err(ExtractError::Unsupported(
            "SAP PSE encrypted PIN is too large".to_owned(),
        ));
    }
    if salt.len() > 32 {
        return Err(ExtractError::Unsupported(
            "SAP PSE salt is too large".to_owned(),
        ));
    }
    if encrypted_pin.is_empty() || salt.is_empty() {
        return Err(ExtractError::Invalid(
            "SAP PSE encrypted PIN or salt is empty".to_owned(),
        ));
    }
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "SAP PSE iteration count is zero".to_owned(),
        ));
    }

    Ok(Sappse {
        version: 1,
        fields: format!(
            "{iterations}${}${}$0$${}${}",
            salt.len(),
            crate::format::hex(salt),
            encrypted_pin.len(),
            crate::format::hex(encrypted_pin)
        ),
    })
}

impl Extractor for SappseExtractor {
    fn slug(&self) -> &'static str {
        Sappse::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match artifact.primary().read_all() {
            Ok(data) if data.first() == Some(&TAG_SEQUENCE) => {}
            _ => return Probe::No,
        }
        match parse(artifact) {
            Ok(_) => Probe::yes("SAP PSE encrypted v2 container"),
            Err(ExtractError::Invalid(reason)) if reason.starts_with("SAP PSE file has tag") => {
                Probe::No
            }
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
