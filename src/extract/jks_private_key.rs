//! Java KeyStore private key extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::JksPrivateKey;
use omniex::{HashType, HashValue};

const JKS_MAX_BYTES: u64 = 16 * 1024 * 1024;

const JKS_MAGIC: u32 = 0xfeed_feed;
const JCEKS_MAGIC: u32 = 0xcece_cece;
const KEY_PROTECTOR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
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
}

/// A keystore parser with sequential big-endian reads.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        let end = self
            .pos
            .checked_add(4)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated keystore field".to_owned()))?;
        let mut number = 0u32;
        for byte in &self.data[self.pos..end] {
            number = (number << 8) | u32::from(*byte);
        }
        self.pos = end;
        Ok(number)
    }

    fn skip(&mut self, length: usize) -> Result<(), ExtractError> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated keystore field".to_owned()))?;
        self.pos = end;
        Ok(())
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated keystore field".to_owned()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn utf(&mut self) -> Result<String, ExtractError> {
        let end = self
            .pos
            .checked_add(2)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated keystore string".to_owned()))?;
        let length = usize::from(u16::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
        ]));
        self.pos = end;
        let bytes = self.bytes(length)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

struct PrivateEntry {
    alias: String,
    protected_key: Vec<u8>,
    certificate: Vec<u8>,
}

struct Keystore {
    entries: Vec<PrivateEntry>,
}

fn parse_encrypted_private_key(data: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let mut outer = Der::new(data);
    let mut info = outer.sequence()?;
    let mut algorithm = info.sequence()?;
    let oid = algorithm.value(0x06, "key protection OID")?;
    if oid != KEY_PROTECTOR_OID {
        return Err(ExtractError::Unsupported(
            "keystore entry does not use the JKS key protector".to_owned(),
        ));
    }
    info.value(0x04, "protected key").map(ToOwned::to_owned)
}

/// Returns the encoded AlgorithmIdentifier of a certificate's public key.
fn certificate_algorithm(certificate: &[u8]) -> Result<&[u8], ExtractError> {
    let mut outer = Der::new(certificate);
    let mut parsed = outer.sequence()?;
    let mut tbs = parsed.sequence()?;
    if tbs.peek_tag() == Some(0xa0) {
        tbs.skip_explicit()?;
    }
    tbs.value(0x02, "serial number")?;
    tbs.sequence()?;
    tbs.sequence()?;
    tbs.sequence()?;
    tbs.sequence()?;
    let mut spki = tbs.sequence()?;
    let start = spki.pos;
    let (tag, _) = spki.tlv()?;
    if tag != 0x30 {
        return Err(ExtractError::Invalid(
            "certificate public key algorithm is not a SEQUENCE".to_owned(),
        ));
    }
    Ok(&spki.data[start..spki.pos])
}

impl<'a> Der<'a> {
    fn skip_explicit(&mut self) -> Result<(), ExtractError> {
        let (tag, _) = self.tlv()?;
        if tag != 0xa0 {
            return Err(ExtractError::Invalid(
                "expected explicit version field".to_owned(),
            ));
        }
        Ok(())
    }
}

fn parse_keystore(data: &[u8]) -> Result<Keystore, ExtractError> {
    let mut reader = Reader::new(data);
    let magic = reader.u32()?;
    if magic != JKS_MAGIC && magic != JCEKS_MAGIC {
        return Err(ExtractError::Unsupported("not a JKS keystore".to_owned()));
    }
    let version = reader.u32()?;
    if version != 1 && version != 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported JKS version {version}"
        )));
    }
    let count = reader.u32()?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let tag = reader.u32()?;
        match tag {
            1 => {
                let alias = reader.utf()?;
                reader.skip(8)?;
                let length = usize::try_from(reader.u32()?)
                    .map_err(|_| ExtractError::Invalid("key is too long".to_owned()))?;
                let protected_key = reader.bytes(length)?.to_vec();
                let certificates = reader.u32()?;
                let mut certificate = None;
                for _ in 0..certificates {
                    if version == 2 {
                        reader.utf()?;
                    }
                    let length = usize::try_from(reader.u32()?)
                        .map_err(|_| ExtractError::Invalid("certificate is too long".to_owned()))?;
                    let bytes = reader.bytes(length)?;
                    if certificate.is_none() {
                        certificate = Some(bytes.to_vec());
                    }
                }
                let certificate = certificate.ok_or_else(|| {
                    ExtractError::Unsupported(
                        "JKS private key entry has no certificate chain".to_owned(),
                    )
                })?;
                entries.push(PrivateEntry {
                    alias,
                    protected_key,
                    certificate,
                });
            }
            2 => {
                reader.utf()?;
                reader.skip(8)?;
                if version == 2 {
                    reader.utf()?;
                }
                let length = usize::try_from(reader.u32()?)
                    .map_err(|_| ExtractError::Invalid("certificate is too long".to_owned()))?;
                reader.bytes(length)?;
            }
            other => {
                return Err(ExtractError::Invalid(format!(
                    "unrecognized keystore entry tag {other}"
                )));
            }
        }
    }
    Ok(Keystore { entries })
}

fn plaintext_prefix(
    algorithm: &[u8],
    plaintext_length: usize,
) -> Result<([u8; 1], [u8; 14]), ExtractError> {
    let mut second = [0u8; 14];
    match plaintext_length {
        0..=127 => {
            let bytes = algorithm.get(1..15).ok_or_else(|| {
                ExtractError::Invalid("public key algorithm is too short".to_owned())
            })?;
            second.copy_from_slice(bytes);
        }
        128..=255 => {
            let bytes = algorithm.get(..14).ok_or_else(|| {
                ExtractError::Invalid("public key algorithm is too short".to_owned())
            })?;
            second.copy_from_slice(bytes);
        }
        _ => {
            let bytes = algorithm.get(..13).ok_or_else(|| {
                ExtractError::Invalid("public key algorithm is too short".to_owned())
            })?;
            second[1..14].copy_from_slice(bytes);
        }
    }
    Ok(([0x30], second))
}

fn entry_value(entry: &PrivateEntry) -> Result<JksPrivateKey, ExtractError> {
    let protected = parse_encrypted_private_key(&entry.protected_key)?;
    if protected.len() < 40 {
        return Err(ExtractError::Invalid(
            "JKS protected key is too short".to_owned(),
        ));
    }
    let (iv, rest) = protected.split_at(20);
    let (encrypted_key, checksum) = rest.split_at(rest.len() - 20);
    if encrypted_key.len() < 20 {
        return Err(ExtractError::Invalid(
            "JKS protected key is too short".to_owned(),
        ));
    }

    let algorithm = certificate_algorithm(&entry.certificate)?;
    let (first, second) = plaintext_prefix(algorithm, encrypted_key.len())?;

    let mut keystream_first = [0u8; 1];
    keystream_first[0] = first[0] ^ encrypted_key[0];

    let mut keystream_second = [0u8; 14];
    for (index, byte) in second.iter().enumerate() {
        keystream_second[index] = byte ^ encrypted_key[index + 6];
    }

    Ok(JksPrivateKey {
        checksum: checksum
            .try_into()
            .map_err(|_| ExtractError::Invalid("JKS checksum must be 20 bytes".to_owned()))?,
        iv: iv
            .try_into()
            .map_err(|_| ExtractError::Invalid("JKS salt must be 20 bytes".to_owned()))?,
        encrypted_key: encrypted_key.to_vec(),
        der1: keystream_first,
        der2: keystream_second,
        alias: entry.alias.clone(),
    })
}

enum Parsed {
    Keystore(Keystore),
    Jceks,
}

fn parse_artifact(artifact: &Artifact) -> Result<Parsed, ExtractError> {
    if artifact.primary().len() > JKS_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the keystore limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.len() < 12 {
        return Err(ExtractError::Unsupported("not a JKS keystore".to_owned()));
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic == JCEKS_MAGIC {
        return Ok(Parsed::Jceks);
    }
    if magic != JKS_MAGIC {
        return Err(ExtractError::Unsupported("not a JKS keystore".to_owned()));
    }
    Ok(Parsed::Keystore(parse_keystore(&data)?))
}

pub struct JksPrivateKeyExtractor;

impl Extractor for JksPrivateKeyExtractor {
    fn slug(&self) -> &'static str {
        JksPrivateKey::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse_artifact(artifact) {
            Ok(Parsed::Keystore(_)) => Probe::yes("JKS keystore signature"),
            Ok(Parsed::Jceks) => {
                Probe::maybe("JCEKS keystore; only JKS-protected keys are modeled")
            }
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        match parse_artifact(artifact)? {
            Parsed::Keystore(keystore) => {
                if keystore.entries.is_empty() {
                    return Err(ExtractError::Unsupported(
                        "keystore has no private key entries".to_owned(),
                    ));
                }
                let mut extracted = Vec::with_capacity(keystore.entries.len());
                for entry in &keystore.entries {
                    extracted.push(Box::new(entry_value(entry)?) as Box<dyn HashValue>);
                }
                Ok(extracted)
            }
            Parsed::Jceks => Err(ExtractError::Unsupported(
                "JCEKS private keys use a different key protector".to_owned(),
            )),
        }
    }
}
