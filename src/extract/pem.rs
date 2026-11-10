//! PKCS#8 PBES2 private key extraction into the John `PEM` serialization.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::PemJohn;
use omniex::{HashType, HashValue};

const PEM_MAX_BYTES: u64 = 4 * 1024 * 1024;

const BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const END: &str = "-----END ENCRYPTED PRIVATE KEY-----";

const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_HMAC_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07];
const OID_HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
const OID_HMAC_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
const OID_AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
const OID_AES192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8]), ExtractError> {
        let tag = *self
            .data
            .get(self.pos)
            .ok_or_else(|| ExtractError::Invalid("truncated DER tag".to_owned()))?;
        self.pos += 1;
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?;
        self.pos += 1;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(ExtractError::Invalid("invalid DER length".to_owned()));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self
                    .data
                    .get(self.pos)
                    .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?;
                length = (length << 8) | usize::from(byte);
                self.pos += 1;
            }
            length
        };
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("DER value runs past the input".to_owned()))?;
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok((tag, value))
    }

    fn value(&mut self, tag: u8, what: &str) -> Result<&'a [u8], ExtractError> {
        let (actual, value) = self.tlv()?;
        if actual != tag {
            return Err(ExtractError::Invalid(format!("expected {what} DER tag")));
        }
        Ok(value)
    }

    fn sequence(&mut self) -> Result<Der<'a>, ExtractError> {
        Ok(Der::new(self.value(0x30, "SEQUENCE")?))
    }

    fn integer(&mut self, what: &str) -> Result<u32, ExtractError> {
        let value = self.value(0x02, what)?;
        if value.is_empty() || value.len() > 4 {
            return Err(ExtractError::Invalid(format!("invalid {what} integer")));
        }
        let mut number = 0u32;
        for byte in value {
            number = (number << 8) | u32::from(*byte);
        }
        Ok(number)
    }

    fn oid(&mut self, what: &str) -> Result<&'a [u8], ExtractError> {
        self.value(0x06, what)
    }
}

fn decode_armor(text: &str) -> Result<Vec<u8>, ExtractError> {
    let Some(start) = text.find(BEGIN) else {
        return Err(ExtractError::Unsupported(
            "missing encrypted private key armor".to_owned(),
        ));
    };
    let body_start = start + BEGIN.len();
    let body_end = text[body_start..]
        .find(END)
        .map(|offset| body_start + offset)
        .ok_or_else(|| ExtractError::Invalid("unterminated PEM armor".to_owned()))?;
    let body: String = text[body_start..body_end]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    omniex::parse::decode_base64(&body, body_start)
        .map_err(|error| ExtractError::Invalid(format!("invalid PEM base64: {error}")))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prf {
    Sha1,
    Sha256,
    Sha512,
}

impl Prf {
    const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

fn cipher_name(cipher: u8) -> &'static str {
    match cipher {
        1 => "des3_cbc",
        2 => "aes128_cbc",
        3 => "aes192_cbc",
        4 => "aes256_cbc",
        _ => "unknown",
    }
}

fn cipher_label(cipher: u8) -> &'static str {
    match cipher {
        1 => "3DES",
        2 => "AES-128",
        3 => "AES-192",
        4 => "AES-256",
        _ => "unknown",
    }
}

struct KeyParts {
    cipher: u8,
    prf: Prf,
    salt: [u8; 8],
    iterations: u32,
    iv: Vec<u8>,
    data: Vec<u8>,
}

fn parse_private_key(der: &[u8]) -> Result<KeyParts, ExtractError> {
    let mut outer = Der::new(der);
    let mut info = outer.sequence()?;

    let mut algorithm = info.sequence()?;
    let encryption_algorithm = algorithm.oid("encryption algorithm")?;
    if encryption_algorithm != OID_PBES2 {
        return Err(ExtractError::Unsupported(
            "unsupported PKCS#8 encryption algorithm".to_owned(),
        ));
    }
    let mut parameters = algorithm.sequence()?;

    let mut kdf = parameters.sequence()?;
    let kdf_algorithm = kdf.oid("key derivation function")?;
    if kdf_algorithm != OID_PBKDF2 {
        return Err(ExtractError::Unsupported(
            "unsupported PKCS#8 key derivation function".to_owned(),
        ));
    }
    let mut kdf_parameters = kdf.sequence()?;
    let salt = kdf_parameters.value(0x04, "PBKDF2 salt")?;
    let salt: [u8; 8] = salt.try_into().map_err(|_| {
        ExtractError::Unsupported("PBKDF2 salt is not the eight bytes John reads".to_owned())
    })?;
    let iterations = kdf_parameters.integer("PBKDF2 iteration count")?;
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "PBKDF2 iteration count is zero".to_owned(),
        ));
    }

    let mut prf = Prf::Sha1;
    if !kdf_parameters.is_empty() {
        if kdf_parameters.peek_tag() == Some(0x02) {
            kdf_parameters.integer("PBKDF2 key length")?;
        }
        if !kdf_parameters.is_empty() {
            let mut prf_sequence = kdf_parameters.sequence()?;
            let oid = prf_sequence.oid("PBKDF2 PRF")?;
            prf = match oid {
                OID_HMAC_SHA1 => Prf::Sha1,
                OID_HMAC_SHA256 => Prf::Sha256,
                OID_HMAC_SHA512 => Prf::Sha512,
                _ => {
                    return Err(ExtractError::Unsupported(
                        "unsupported PKCS#8 PBKDF2 PRF".to_owned(),
                    ));
                }
            };
        }
    }

    let mut scheme = parameters.sequence()?;
    let cipher_oid = scheme.oid("cipher")?;
    let cipher = match cipher_oid {
        OID_DES_EDE3_CBC => 1,
        OID_AES128_CBC => 2,
        OID_AES192_CBC => 3,
        OID_AES256_CBC => 4,
        _ => {
            return Err(ExtractError::Unsupported(
                "unsupported PKCS#8 cipher".to_owned(),
            ));
        }
    };
    let iv = scheme.value(0x04, "cipher initialization vector")?;
    let expected_iv = if cipher == 1 { 8 } else { 16 };
    if iv.len() != expected_iv {
        return Err(ExtractError::Invalid(format!(
            "cipher initialization vector is not {expected_iv} bytes"
        )));
    }

    let data = info.value(0x04, "encrypted key")?.to_vec();
    let block_size = if cipher == 1 { 8 } else { 16 };
    if data.is_empty() || data.len() % block_size != 0 {
        return Err(ExtractError::Invalid(
            "encrypted key is not a whole number of cipher blocks".to_owned(),
        ));
    }

    Ok(KeyParts {
        cipher,
        prf,
        salt,
        iterations,
        iv: iv.to_vec(),
        data,
    })
}

fn parts_from_artifact(artifact: &Artifact) -> Result<Vec<KeyParts>, ExtractError> {
    if artifact.primary().len() > PEM_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the PEM limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;

    if data.starts_with(&[0x30]) {
        return Ok(vec![parse_private_key(&data)?]);
    }

    let text = String::from_utf8_lossy(&data);
    let mut parts = Vec::new();
    let mut rest = text.as_ref();
    while let Some(offset) = rest.find(BEGIN) {
        let block = &rest[offset..];
        let end = block
            .find(END)
            .map(|end| end + END.len())
            .ok_or_else(|| ExtractError::Invalid("unterminated PEM armor".to_owned()))?;
        match parse_private_key(&decode_armor(&block[..end])?) {
            Ok(part) => parts.push(part),
            Err(ExtractError::Unsupported(_)) => {}
            Err(error) => return Err(error),
        }
        rest = &block[end..];
    }
    if parts.is_empty() {
        return Err(ExtractError::Unsupported(
            "no encrypted PKCS#8 private key found".to_owned(),
        ));
    }
    Ok(parts)
}

fn john_compatible(_part: &KeyParts) -> bool {
    true
}

pub struct PemExtractor;

impl Extractor for PemExtractor {
    fn slug(&self) -> &'static str {
        PemJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parts_from_artifact(artifact) {
            Ok(parts) if parts.iter().any(john_compatible) => {
                let part = parts.first().expect("non-empty parts");
                Probe::yes(format!(
                    "encrypted PKCS#8 private key using PBKDF2-HMAC-{} with {}",
                    part.prf.name().to_ascii_uppercase(),
                    cipher_label(part.cipher),
                ))
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let parts = parts_from_artifact(artifact)?;
        let parts: Vec<KeyParts> = parts.into_iter().filter(john_compatible).collect();
        if parts.is_empty() {
            return Err(ExtractError::Unsupported(
                "no PEM private key needs the John serialization".to_owned(),
            ));
        }
        let mut extracted = Vec::with_capacity(parts.len());
        for part in parts {
            let length = u32::try_from(part.data.len())
                .map_err(|_| ExtractError::Invalid("private key is too long".to_owned()))?;
            let salt = omniex::format::hex(part.salt);
            let iv = omniex::format::hex(&part.iv);
            let data = omniex::format::hex(&part.data);
            let payload = if part.prf == Prf::Sha1 {
                format!(
                    "1${}${salt}${}${iv}${length}${data}",
                    part.cipher, part.iterations
                )
            } else {
                format!(
                    "2$pbkdf2${}${}${}${salt}${}${iv}${length}${data}",
                    part.prf.name(),
                    cipher_name(part.cipher),
                    part.cipher,
                    part.iterations,
                )
            };
            extracted.push(Box::new(PemJohn { data: payload }) as Box<dyn HashValue>);
        }
        Ok(extracted)
    }
}
