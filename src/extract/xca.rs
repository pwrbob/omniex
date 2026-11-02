//! XCA database extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Xca;
use crate::{HashType, HashValue};

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const KEY: &[u8] = b"pwhash";
const SALT_HEX: usize = 16;
const DIGEST_HEX: usize = 128;
const OPTIONAL_SCAN_WINDOW: usize = 1024;

pub struct XcaExtractor;

fn hex_value(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn password_hash(data: &[u8], start: usize) -> Option<String> {
    let value = data.get(start..start + 1 + SALT_HEX + DIGEST_HEX)?;
    if value[0] != b'T' {
        return None;
    }
    let hex = &value[1..];
    if hex[..SALT_HEX].iter().all(|byte| hex_value(*byte))
        && hex[SALT_HEX..].iter().all(|byte| hex_value(*byte))
    {
        Some(String::from_utf8_lossy(hex).into_owned())
    } else {
        None
    }
}

fn scan_hashes(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let source = artifact.primary();
    let len = source.len();
    if len < 512 {
        return Err(ExtractError::Unsupported(
            "not an XCA SQLite database".to_owned(),
        ));
    }
    let mut header = [0; 100];
    source.read_exact_at(0, &mut header).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if &header[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
        return Err(ExtractError::Unsupported(
            "missing SQLite database signature".to_owned(),
        ));
    }
    let page_size = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if page_size == 1 {
        65536
    } else {
        usize::from(page_size)
    };
    if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
        return Err(ExtractError::Invalid(
            "XCA SQLite page size is invalid".to_owned(),
        ));
    }

    let window = (1 << 20) as u64;
    let mut offset = 0;
    let mut hashes: Vec<String> = Vec::new();
    while offset < len {
        let available = (len - offset).min(window + OPTIONAL_SCAN_WINDOW as u64);
        let mut buffer = vec![0; available as usize];
        source.read_exact_at(offset, &mut buffer).map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let searchable = (available as usize).min(window as usize);
        for index in 0..searchable {
            if !buffer[index..].starts_with(KEY) {
                continue;
            }
            if let Some(hash) = password_hash(&buffer, index + KEY.len()) {
                if !hashes.contains(&hash) {
                    hashes.push(hash);
                }
            }
        }
        offset += window;
    }

    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "XCA database has no password hash".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for XcaExtractor {
    fn slug(&self) -> &'static str {
        Xca::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match scan_hashes(artifact) {
            Ok(_) => Probe::yes("XCA SQLite settings password hash"),
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
            Err(ExtractError::Unsupported(_)) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let hashes = scan_hashes(artifact)?;
        Ok(hashes
            .into_iter()
            .map(|payload| Box::new(Xca { payload }) as Box<dyn HashValue>)
            .collect())
    }
}
