//! BitShares SQLite and LevelDB wallet extraction.

use std::collections::HashSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::Bitshares;
use crate::{HashType, HashValue};

pub struct BitsharesWalletExtractor;

const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";
const CHUNK: usize = 64 * 1024;
const OVERLAP: usize = 512;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_digest(text: &[u8]) -> Option<[u8; 64]> {
    if text.len() != 128 {
        return None;
    }
    let mut digest = [0; 64];
    for (index, pair) in text.as_chunks::<2>().0.iter().enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return offsets;
    }
    let mut index = 0;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            offsets.push(index);
            index += needle.len();
        } else {
            index += 1;
        }
    }
    offsets
}

fn after_whitespace(data: &[u8], mut index: usize) -> usize {
    while data.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn sqlite_values(chunk: &[u8], base: u64, found: &mut Vec<(u64, [u8; 64])>) {
    let marker = b"\"encryption_key\"";
    for offset in find_all(chunk, marker) {
        let mut index = offset + marker.len();
        index = after_whitespace(chunk, index);
        if chunk.get(index) != Some(&b':') {
            continue;
        }
        index = after_whitespace(chunk, index + 1);
        if chunk.get(index) != Some(&b'"') {
            continue;
        }
        let start = index + 1;
        let Some(text) = chunk.get(start..start + 128) else {
            continue;
        };
        if chunk.get(start + 128) != Some(&b'"') {
            continue;
        }
        if let Some(digest) = decode_digest(text) {
            found.push((base + offset as u64, digest));
        }
    }
}

fn leveldb_values(chunk: &[u8], base: u64, found: &mut Vec<(u64, [u8; 64])>) {
    for offset in find_all(chunk, b"checksum") {
        let start = offset + b"checksum".len() + 3;
        let Some(text) = chunk.get(start..start + 128) else {
            continue;
        };
        if let Some(digest) = decode_digest(text) {
            found.push((base + offset as u64, digest));
        }
    }
}

fn scan(source: &dyn ReadAt, sqlite: bool) -> Result<Vec<(u64, [u8; 64])>, ExtractError> {
    let length = source.len();
    let mut found = Vec::new();
    let mut offset = 0;
    while offset < length {
        let mut buffer = vec![0; CHUNK];
        let read = source.read_at(offset, &mut buffer).map_err(|error| {
            ExtractError::Invalid(format!("cannot read BitShares wallet: {error}"))
        })?;
        if read == 0 {
            break;
        }
        buffer.truncate(read);
        if sqlite {
            sqlite_values(&buffer, offset, &mut found);
        } else {
            leveldb_values(&buffer, offset, &mut found);
        }
        if offset + read as u64 >= length {
            break;
        }
        let advance = read.saturating_sub(OVERLAP);
        offset += advance.max(1) as u64;
    }

    found.sort_by_key(|(offset, _)| *offset);
    let mut seen = HashSet::new();
    found.retain(|(_, digest)| seen.insert(*digest));
    Ok(found)
}

fn parse(artifact: &Artifact) -> Result<Vec<Bitshares>, ExtractError> {
    let source = artifact.primary();
    if source.is_empty() {
        return Err(ExtractError::Invalid(
            "BitShares wallet is empty".to_owned(),
        ));
    }
    let mut header = [0; 16];
    let read = source.read_at(0, &mut header).map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let sqlite = read == SQLITE_HEADER.len() && header == SQLITE_HEADER;

    let found = scan(source, sqlite)?;
    if found.is_empty() {
        return Err(ExtractError::Unsupported(
            "BitShares wallet has no encrypted key".to_owned(),
        ));
    }
    Ok(found
        .into_iter()
        .map(|(_, digest)| Bitshares { digest })
        .collect())
}

impl Extractor for BitsharesWalletExtractor {
    fn slug(&self) -> &'static str {
        Bitshares::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let mut header = [0; 16];
        let read = source.read_at(0, &mut header).unwrap_or(0);
        let sqlite = read == SQLITE_HEADER.len() && header == SQLITE_HEADER;
        match parse(artifact) {
            Ok(_values) if sqlite => Probe::yes("BitShares SQLite wallet"),
            Ok(values) if !sqlite && !values.is_empty() => Probe::yes("BitShares LevelDB wallet"),
            Ok(_) => Probe::No,
            Err(_) if sqlite => Probe::maybe("SQLite database without a BitShares wallet"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
