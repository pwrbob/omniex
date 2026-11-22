//! Telegram Desktop local storage extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Telegram;
use crate::{HashType, HashValue};

pub struct TelegramExtractor;

const MAGIC: &[u8; 4] = b"TDF$";
const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 288;
const RECORD_HEADER: usize = 4 + 4 + 4 + SALT_SIZE + 4 + KEY_SIZE;
const PROBE_WINDOW: u64 = 1 << 20;

fn record_at(artifact: &Artifact, offset: u64) -> Option<Telegram> {
    if offset + RECORD_HEADER as u64 > artifact.primary().len() {
        return None;
    }
    let mut header = [0; 8];
    artifact.primary().read_exact_at(offset, &mut header).ok()?;
    if &header[..4] != MAGIC {
        return None;
    }

    let mut length = [0; 4];
    artifact
        .primary()
        .read_exact_at(offset + 8, &mut length)
        .ok()?;
    if u32::from_be_bytes(length) as usize != SALT_SIZE {
        return None;
    }
    let mut salt = [0; SALT_SIZE];
    artifact
        .primary()
        .read_exact_at(offset + 12, &mut salt)
        .ok()?;

    artifact
        .primary()
        .read_exact_at(offset + 12 + SALT_SIZE as u64, &mut length)
        .ok()?;
    if u32::from_be_bytes(length) as usize != KEY_SIZE {
        return None;
    }
    let mut key = [0; KEY_SIZE];
    artifact
        .primary()
        .read_exact_at(offset + 16 + SALT_SIZE as u64, &mut key)
        .ok()?;

    Some(Telegram {
        version: 1,
        iterations: 4000,
        salt: salt.to_vec(),
        digest: key.to_vec(),
    })
}

fn scan(artifact: &Artifact, window: u64) -> Result<Vec<Telegram>, ExtractError> {
    let len = artifact.primary().len().min(window);
    let mut hashes = Vec::new();
    let mut offsets = Vec::new();
    let mut start = 0;
    let chunk_size = 1024 * 1024;

    while start + 4 <= len {
        let read_len = usize::try_from((len - start).min(chunk_size as u64))
            .map_err(|_| ExtractError::Invalid("artifact is too large".to_owned()))?;
        let mut chunk = vec![0; read_len];
        artifact
            .primary()
            .read_exact_at(start, &mut chunk)
            .map_err(|error| {
                ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
            })?;

        for index in 0..chunk.len().saturating_sub(3) {
            if &chunk[index..index + 4] != MAGIC {
                continue;
            }
            let offset = start + index as u64;
            if offsets.contains(&offset) {
                continue;
            }
            if let Some(hash) = record_at(artifact, offset) {
                offsets.push(offset);
                hashes.push(hash);
            }
        }

        if start + read_len as u64 >= len {
            break;
        }
        start += (read_len - 3) as u64;
    }

    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Telegram Desktop local storage record found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for TelegramExtractor {
    fn slug(&self) -> &'static str {
        Telegram::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan(artifact, PROBE_WINDOW) {
            Ok(_) => Probe::yes("Telegram Desktop local storage map"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(scan(artifact, u64::MAX)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
