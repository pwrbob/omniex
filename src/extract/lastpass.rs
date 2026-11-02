//! LastPass vault extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Lastpass;
use crate::{HashType, HashValue};

pub struct LastpassExtractor;

struct Vault {
    encrypted: Vec<u8>,
    iv: Vec<u8>,
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value.trim())
        .or_else(|_| STANDARD_NO_PAD.decode(value.trim()))
        .ok()
}

fn vault_blob(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.starts_with(b"LPAV") {
        return Ok(data);
    }
    if let Some(rest) = data.strip_prefix(b"LPB64") {
        return decode_base64(&String::from_utf8_lossy(rest))
            .filter(|blob| blob.starts_with(b"LPAV"))
            .ok_or_else(|| ExtractError::Invalid("invalid LastPass LPB64 payload".to_owned()));
    }
    if let Ok(text) = str::from_utf8(&data) {
        for line in text.lines() {
            if let Some(blob) = decode_base64(line.trim()) {
                if blob.starts_with(b"LPAV") {
                    return Ok(blob);
                }
            }
        }
    }
    Err(ExtractError::Unsupported("not a LastPass vault".to_owned()))
}

fn parse_encu(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ExtractError> {
    let text = str::from_utf8(data)
        .map_err(|_| ExtractError::Invalid("LastPass ENCU record is not UTF-8".to_owned()))?;
    let text = text.trim();
    let Some(rest) = text.strip_prefix('!') else {
        return Err(ExtractError::Unsupported(
            "LastPass ENCU record has no initialization vector".to_owned(),
        ));
    };
    let (iv, encrypted) = rest
        .split_once('|')
        .ok_or_else(|| ExtractError::Invalid("invalid LastPass ENCU record".to_owned()))?;
    let iv = decode_base64(iv)
        .ok_or_else(|| ExtractError::Invalid("invalid LastPass ENCU IV".to_owned()))?;
    let encrypted = decode_base64(encrypted)
        .ok_or_else(|| ExtractError::Invalid("invalid LastPass ENCU data".to_owned()))?;
    if iv.len() != 16 {
        return Err(ExtractError::Invalid(
            "LastPass ENCU IV must be 16 bytes".to_owned(),
        ));
    }
    if encrypted.len() != 16 {
        return Err(ExtractError::Unsupported(
            "LastPass ENCU email is not a single AES block".to_owned(),
        ));
    }
    Ok((encrypted, iv))
}

fn vault(artifact: &Artifact) -> Result<Vault, ExtractError> {
    let blob = vault_blob(artifact)?;
    let mut offset = 0;
    while offset + 8 <= blob.len() {
        let identifier = &blob[offset..offset + 4];
        let size = BigEndian::read_u32(&blob[offset + 4..offset + 8]) as usize;
        offset += 8;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= blob.len())
            .ok_or_else(|| ExtractError::Invalid("truncated LastPass vault record".to_owned()))?;
        if identifier == b"ENCU" {
            let (encrypted, iv) = parse_encu(&blob[offset..end])?;
            return Ok(Vault { encrypted, iv });
        }
        offset = end;
    }
    Err(ExtractError::Unsupported(
        "LastPass vault has no ENCU record".to_owned(),
    ))
}

fn text_member(artifact: &Artifact, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        artifact
            .member(name)
            .and_then(|source| source.read_all().ok())
            .and_then(|data| String::from_utf8(data).ok())
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    })
}

fn username(artifact: &Artifact) -> Option<String> {
    text_member(artifact, &["username", "email"]).map(|name| name.to_lowercase())
}

fn iterations(artifact: &Artifact) -> Option<u32> {
    text_member(artifact, &["iterations", "iter"])
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|iterations| *iterations > 0)
}

fn build(artifact: &Artifact) -> Result<Lastpass, ExtractError> {
    let vault = vault(artifact)?;
    let username = username(artifact).ok_or_else(|| {
        ExtractError::Unsupported(
            "missing LastPass username companion (`username` or `email`)".to_owned(),
        )
    })?;
    let iterations = iterations(artifact).ok_or_else(|| {
        ExtractError::Unsupported("missing LastPass iteration companion".to_owned())
    })?;
    Ok(Lastpass {
        digest: vault
            .encrypted
            .as_slice()
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid LastPass digest".to_owned()))?,
        iterations,
        username,
        hash: vault
            .iv
            .as_slice()
            .try_into()
            .map_err(|_| ExtractError::Invalid("invalid LastPass IV".to_owned()))?,
    })
}

impl Extractor for LastpassExtractor {
    fn slug(&self) -> &'static str {
        Lastpass::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if vault(artifact).is_err() {
            return Probe::No;
        }
        if username(artifact).is_none() || iterations(artifact).is_none() {
            return Probe::Maybe(
                "LastPass vault needs `username` and `iterations` companions".to_owned(),
            );
        }
        Probe::yes("LastPass vault ENCU record")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(build(artifact)?) as Box<dyn HashValue>])
    }
}
