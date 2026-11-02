//! PKCS#12 PFX MAC extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pkcs12;
use crate::{HashType, HashValue};

pub struct Pkcs12Extractor;

const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xa0;

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
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
            .ok_or_else(|| ExtractError::Invalid("truncated PKCS#12 DER value".to_owned()))?;
        let Some((&first, rest)) = rest.split_first() else {
            return Err(ExtractError::Invalid(
                "truncated PKCS#12 DER length".to_owned(),
            ));
        };
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(ExtractError::Invalid(
                    "invalid PKCS#12 DER length".to_owned(),
                ));
            }
            let mut length = 0usize;
            for byte in &rest[..count] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| {
                        ExtractError::Invalid("PKCS#12 DER length is too large".to_owned())
                    })?;
            }
            (length, &rest[count..])
        };
        let (value, rest) = rest
            .split_at_checked(length)
            .ok_or_else(|| ExtractError::Invalid("truncated PKCS#12 DER value".to_owned()))?;
        Ok((tag, value, rest))
    }
}

fn expect_tag<'a>(der: &mut Der<'a>, tag: u8, what: &str) -> Result<&'a [u8], ExtractError> {
    let (actual, value) = der.value()?;
    if actual != tag {
        return Err(ExtractError::Invalid(format!(
            "PKCS#12 {what} has tag 0x{actual:02x}, expected 0x{tag:02x}"
        )));
    }
    Ok(value)
}

fn parse_integer(value: &[u8]) -> Result<u64, ExtractError> {
    if value.is_empty() || value.len() > 8 {
        return Err(ExtractError::Invalid("invalid PKCS#12 integer".to_owned()));
    }
    let mut result = 0u64;
    for byte in value {
        result = result * 256 + u64::from(*byte);
    }
    Ok(result)
}

fn parse(artifact: &Artifact) -> Result<Pkcs12, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut outer = Der::new(&data);
    let root = expect_tag(&mut outer, TAG_SEQUENCE, "PFX")?;
    let mut pfx = Der::new(root);
    let _version = parse_integer(expect_tag(&mut pfx, TAG_INTEGER, "version")?)?;

    let auth_safe = expect_tag(&mut pfx, TAG_SEQUENCE, "authSafe ContentInfo")?;
    let mut content_info = Der::new(auth_safe);
    let content_type = expect_tag(&mut content_info, TAG_OID, "content type")?;
    if content_type != OID_DATA {
        return Err(ExtractError::Unsupported(
            "PKCS#12 authSafe is not password-protected data".to_owned(),
        ));
    }
    let explicit = expect_tag(&mut content_info, TAG_CONTEXT_0, "content")?;
    let mut explicit = Der::new(explicit);
    let authenticated_safe = expect_tag(&mut explicit, TAG_OCTET_STRING, "authenticated safe")?;
    if authenticated_safe.is_empty() {
        return Err(ExtractError::Invalid(
            "PKCS#12 authenticated safe is empty".to_owned(),
        ));
    }

    if pfx.is_empty() {
        return Err(ExtractError::Unsupported(
            "PKCS#12 file has no MAC data".to_owned(),
        ));
    }
    let mac_data = expect_tag(&mut pfx, TAG_SEQUENCE, "MAC data")?;
    let mut mac_data = Der::new(mac_data);
    let digest_info = expect_tag(&mut mac_data, TAG_SEQUENCE, "DigestInfo")?;
    let mut digest_info = Der::new(digest_info);
    let algorithm = expect_tag(&mut digest_info, TAG_SEQUENCE, "MAC algorithm identifier")?;
    let mut algorithm = Der::new(algorithm);
    let oid = expect_tag(&mut algorithm, TAG_OID, "MAC algorithm OID")?;
    let version = if oid == OID_SHA1 {
        1
    } else if oid == OID_SHA256 {
        256
    } else {
        return Err(ExtractError::Unsupported(
            "unsupported PKCS#12 MAC algorithm".to_owned(),
        ));
    };
    let mac = expect_tag(&mut digest_info, TAG_OCTET_STRING, "MAC digest")?;
    let expected_mac_length = if version == 1 { 20 } else { 32 };
    if mac.len() != expected_mac_length {
        return Err(ExtractError::Invalid(format!(
            "PKCS#12 MAC digest has length {}, expected {expected_mac_length}",
            mac.len()
        )));
    }

    let salt = expect_tag(&mut mac_data, TAG_OCTET_STRING, "MAC salt")?;
    if !(8..=64).contains(&salt.len()) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported PKCS#12 MAC salt length {}",
            salt.len()
        )));
    }
    let iterations = if mac_data.is_empty() {
        1
    } else {
        parse_integer(expect_tag(&mut mac_data, TAG_INTEGER, "iteration count")?)?
    };
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "PKCS#12 iteration count is zero".to_owned(),
        ));
    }
    let iterations = u32::try_from(iterations)
        .map_err(|_| ExtractError::Invalid("PKCS#12 iteration count is too large".to_owned()))?;
    let length = u32::try_from(authenticated_safe.len())
        .map_err(|_| ExtractError::Invalid("PKCS#12 authenticated safe is too large".to_owned()))?;

    Ok(Pkcs12 {
        version,
        iterations,
        salt_length: u32::try_from(salt.len())
            .map_err(|_| ExtractError::Invalid("PKCS#12 salt is too large".to_owned()))?,
        salt: salt.to_vec(),
        length,
        data: authenticated_safe.to_vec(),
        mac: mac.to_vec(),
    })
}

impl Extractor for Pkcs12Extractor {
    fn slug(&self) -> &'static str {
        Pkcs12::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) if !data.is_empty() => data,
            _ => return Probe::No,
        };
        if data.first() != Some(&TAG_SEQUENCE) {
            return Probe::No;
        }
        match parse(artifact) {
            Ok(_) => Probe::yes("PKCS#12 PFX MAC structure"),
            Err(ExtractError::Invalid(reason))
                if reason.starts_with("PKCS#12 PFX has tag")
                    || reason.starts_with("PKCS#12 authSafe ContentInfo has tag") =>
            {
                Probe::No
            }
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
