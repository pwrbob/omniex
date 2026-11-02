//! LUKS version 2 volume header extraction.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use byteorder::{BigEndian, ByteOrder};
use serde_json::Value;

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe};
use omniex::types::LuksV2;
use omniex::{HashType, HashValue};

pub struct LuksV2Extractor;

const MAGIC: &[u8] = b"LUKS\xba\xbe";
const JSON_OFFSET: u64 = 0x1000;
const JSON_SIZE: usize = 32768;

fn read(artifact: &Artifact, offset: u64, len: usize, what: &str) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; len];
    artifact
        .primary()
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read {what}: {error}")))?;
    Ok(data)
}

fn number(value: &Value, name: &str) -> Result<u32, ExtractError> {
    let raw = value
        .get(name)
        .ok_or_else(|| ExtractError::Invalid(format!("LUKS v2 header is missing {name}")))?;
    if let Some(number) = raw.as_u64() {
        return u32::try_from(number)
            .map_err(|_| ExtractError::Invalid(format!("LUKS v2 {name} is too large")));
    }
    raw.as_str()
        .and_then(|text| text.parse::<u32>().ok())
        .ok_or_else(|| ExtractError::Invalid(format!("invalid LUKS v2 {name}")))
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, ExtractError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ExtractError::Invalid(format!("LUKS v2 header is missing {name}")))
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Value, ExtractError> {
    value
        .get(name)
        .filter(|value| value.is_object())
        .ok_or_else(|| ExtractError::Invalid(format!("LUKS v2 header is missing {name}")))
}

fn keyslot(
    artifact: &Artifact,
    slot: &Value,
    first_sector: &[u8],
) -> Result<Option<LuksV2>, ExtractError> {
    if slot.get("type").and_then(Value::as_str) == Some("reencrypt") {
        return Ok(None);
    }
    let area = object(slot, "area")?;
    let af = object(slot, "af")?;
    let kdf = object(slot, "kdf")?;

    let key_size = number(slot, "key_size")?;
    if !matches!(key_size, 16 | 32 | 64) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v2 key size {key_size}"
        )));
    }
    let stripes = number(af, "stripes")?;
    if stripes == 0 {
        return Err(ExtractError::Invalid(
            "LUKS v2 keyslot stripe count is zero".to_owned(),
        ));
    }
    let af_len = usize::try_from(key_size)
        .ok()
        .and_then(|bytes| bytes.checked_mul(stripes as usize))
        .ok_or_else(|| ExtractError::Invalid("LUKS v2 keyslot is too large".to_owned()))?;
    if !(64_000..=256_000).contains(&af_len) {
        return Err(ExtractError::Unsupported(format!(
            "LUKS v2 keyslot data length {af_len} is unsupported"
        )));
    }
    let offset = u64::from(number(area, "offset")?);
    let data = read(artifact, offset, af_len, "LUKS v2 keyslot data")?;

    let encryption = string(area, "encryption")?;
    let (cipher, cipher_mode) = encryption.split_once('-').ok_or_else(|| {
        ExtractError::Invalid(format!("invalid LUKS v2 keyslot encryption {encryption}"))
    })?;
    if cipher != "aes"
        || !matches!(
            cipher_mode,
            "cbc-essiv:sha256" | "cbc-plain" | "cbc-plain64" | "xts-plain" | "xts-plain64"
        )
    {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v2 keyslot encryption {encryption}"
        )));
    }

    let kdf_type = string(kdf, "type")?;
    if !matches!(kdf_type, "argon2i" | "argon2id") {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v2 KDF {kdf_type}"
        )));
    }
    let hash = string(af, "hash")?;
    if hash != "sha256" {
        return Err(ExtractError::Unsupported(format!(
            "unsupported LUKS v2 anti-forensic hash {hash}"
        )));
    }
    let salt = STANDARD
        .decode(string(kdf, "salt")?)
        .map_err(|_| ExtractError::Invalid("invalid LUKS v2 base64 salt".to_owned()))?;
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| ExtractError::Invalid("LUKS v2 salt must be 32 bytes".to_owned()))?;
    let mut ciphertext = [0u8; 512];
    ciphertext.copy_from_slice(first_sector);

    Ok(Some(LuksV2 {
        kdf: kdf_type.to_owned(),
        hash: hash.to_owned(),
        cipher: cipher.to_owned(),
        cipher_mode: cipher_mode.to_owned(),
        key_bytes: u16::try_from(key_size * 8)
            .map_err(|_| ExtractError::Invalid("LUKS v2 key size is too large".to_owned()))?,
        memory: number(kdf, "memory")?,
        iterations: number(kdf, "time")?,
        parallelism: number(kdf, "cpus")?,
        salt,
        af: data,
        ciphertext,
    }))
}

fn parse(artifact: &Artifact) -> Result<Vec<LuksV2>, ExtractError> {
    let preheader = read(artifact, 0, 8, "LUKS v2 preheader")?;
    if preheader.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ExtractError::Unsupported("LUKS magic not found".to_owned()));
    }
    if BigEndian::read_u16(&preheader[6..8]) != 2 {
        return Err(ExtractError::Unsupported("not a LUKS v2 header".to_owned()));
    }

    let mut json = read(artifact, JSON_OFFSET, JSON_SIZE, "LUKS v2 JSON header")?;
    if let Some(end) = json.iter().position(|byte| *byte == 0) {
        json.truncate(end);
    }
    let header: Value = serde_json::from_slice(&json)
        .map_err(|error| ExtractError::Invalid(format!("invalid LUKS v2 JSON header: {error}")))?;
    let keyslots = object(&header, "keyslots")?;
    let keyslots = keyslots
        .as_object()
        .filter(|slots| !slots.is_empty())
        .ok_or_else(|| ExtractError::Unsupported("no LUKS v2 keyslots".to_owned()))?;
    let segments = object(&header, "segments")?;
    let segment = segments
        .get("0")
        .ok_or_else(|| ExtractError::Invalid("LUKS v2 header is missing segment 0".to_owned()))?;
    let segment_offset = u64::from(number(segment, "offset")?);
    let first_sector = read(artifact, segment_offset, 512, "LUKS v2 segment data")?;
    if first_sector.iter().all(|byte| *byte == 0) {
        return Err(ExtractError::Unsupported(
            "LUKS v2 segment is not initialized".to_owned(),
        ));
    }

    let mut values = Vec::new();
    for slot in keyslots.values() {
        if let Some(value) = keyslot(artifact, slot, &first_sector)? {
            values.push(value);
        }
    }
    if values.is_empty() {
        return Err(ExtractError::Unsupported("no LUKS v2 keyslot".to_owned()));
    }
    Ok(values)
}

impl Extractor for LuksV2Extractor {
    fn slug(&self) -> &'static str {
        LuksV2::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("LUKS v2 JSON header"),
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
