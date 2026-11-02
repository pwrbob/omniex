//! LUKS version 1 volume header extraction.

use byteorder::{BigEndian, ByteOrder};

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::LuksV1;
use omniex::{HashType, HashValue};

pub struct LuksV1Extractor;

const MAGIC: &[u8] = b"LUKS\xba\xbe";
const HEADER_SIZE: usize = 592;
const KEYS_COUNT: usize = 8;
const KEYS_OFFSET: usize = 208;
const KEYS_SLOT_SIZE: usize = 48;
const ENABLED: u32 = 0x00ac_71f3;
const ENABLED_OLD: u32 = 0x0000_cafe;

fn number<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ExtractError> {
    data.get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ExtractError::Invalid("truncated LUKS v1 header".to_owned()))
}

fn text(data: &[u8], offset: usize, len: usize) -> Result<String, ExtractError> {
    let raw = data
        .get(offset..offset + len)
        .ok_or_else(|| ExtractError::Invalid("truncated LUKS v1 header".to_owned()))?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8(raw[..end].to_vec())
        .map_err(|_| ExtractError::Invalid("invalid LUKS v1 text field".to_owned()))
}

fn read(artifact: &Artifact, offset: u64, len: usize, what: &str) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; len];
    artifact
        .primary()
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read {what}: {error}")))?;
    Ok(data)
}

fn parse(artifact: &Artifact) -> Result<Vec<LuksV1>, ExtractError> {
    if artifact.primary().len() < HEADER_SIZE as u64 {
        return Err(ExtractError::Invalid("truncated LUKS v1 header".to_owned()));
    }
    let header = read(artifact, 0, HEADER_SIZE, "LUKS v1 header")?;
    if header.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ExtractError::Unsupported("LUKS magic not found".to_owned()));
    }
    if BigEndian::read_u16(&number::<2>(&header, 6)?) != 1 {
        return Err(ExtractError::Unsupported("not a LUKS v1 header".to_owned()));
    }

    let hash = text(&header, 72, 32)?;
    let cipher = text(&header, 8, 32)?;
    let cipher_mode = text(&header, 40, 32)?;
    if !matches!(hash.as_str(), "sha1" | "sha256" | "sha512" | "ripemd160") {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v1 hash {hash}"
        )));
    }
    if !matches!(cipher.as_str(), "aes" | "serpent" | "twofish") {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v1 cipher {cipher}"
        )));
    }
    if !matches!(
        cipher_mode.as_str(),
        "cbc-essiv:sha256" | "cbc-plain" | "cbc-plain64" | "xts-plain" | "xts-plain64"
    ) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v1 cipher mode {cipher_mode}"
        )));
    }

    let payload_offset = u64::from(BigEndian::read_u32(&number::<4>(&header, 104)?));
    let key_bytes = BigEndian::read_u32(&number::<4>(&header, 108)?);
    if !matches!(key_bytes, 16 | 32 | 64) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v1 key size {key_bytes}"
        )));
    }
    let payload = read(
        artifact,
        payload_offset
            .checked_mul(512)
            .ok_or_else(|| ExtractError::Invalid("LUKS v1 payload offset overflows".to_owned()))?,
        512,
        "LUKS v1 payload",
    )?;
    if payload.iter().all(|byte| *byte == 0) {
        return Err(ExtractError::Unsupported(
            "LUKS v1 payload is not initialized".to_owned(),
        ));
    }
    let mut ciphertext = [0u8; 512];
    ciphertext.copy_from_slice(&payload);

    let mut values = Vec::new();
    for index in 0..KEYS_COUNT {
        let base = KEYS_OFFSET + index * KEYS_SLOT_SIZE;
        let active = BigEndian::read_u32(&number::<4>(&header, base)?);
        if active != ENABLED && active != ENABLED_OLD {
            continue;
        }
        let iterations = BigEndian::read_u32(&number::<4>(&header, base + 4)?);
        if iterations == 0 {
            return Err(ExtractError::Invalid(
                "LUKS v1 keyslot iteration count is zero".to_owned(),
            ));
        }
        let material_offset = u64::from(BigEndian::read_u32(&number::<4>(&header, base + 40)?));
        let stripes = BigEndian::read_u32(&number::<4>(&header, base + 44)?);
        if stripes == 0 {
            return Err(ExtractError::Invalid(
                "LUKS v1 keyslot stripe count is zero".to_owned(),
            ));
        }
        let af_len = usize::try_from(key_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(stripes as usize))
            .ok_or_else(|| ExtractError::Invalid("LUKS v1 keyslot is too large".to_owned()))?;
        if !(64_000..=256_000).contains(&af_len) {
            return Err(ExtractError::Unsupported(format!(
                "LUKS v1 keyslot data length {af_len} is unsupported"
            )));
        }
        let af = read(
            artifact,
            material_offset.checked_mul(512).ok_or_else(|| {
                ExtractError::Invalid("LUKS v1 keyslot offset overflows".to_owned())
            })?,
            af_len,
            "LUKS v1 keyslot data",
        )?;
        let salt = number::<32>(&header, base + 8)?;
        values.push(LuksV1 {
            hash: hash.clone(),
            cipher: cipher.clone(),
            cipher_mode: cipher_mode.clone(),
            key_bytes: u16::try_from(key_bytes * 8)
                .map_err(|_| ExtractError::Invalid("LUKS v1 key size is too large".to_owned()))?,
            iterations,
            salt,
            af,
            ciphertext,
        });
    }
    if values.is_empty() {
        return Err(ExtractError::Unsupported(
            "no active LUKS v1 keyslot".to_owned(),
        ));
    }
    Ok(values)
}

impl Extractor for LuksV1Extractor {
    fn slug(&self) -> &'static str {
        LuksV1::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("LUKS v1 header"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
