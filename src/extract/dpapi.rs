//! Windows DPAPI master key records from hive exports, user masterkey files,
//! and Credential Manager vault data.
//!
//! A masterkey file does not store the account SID or the credential history
//! context. The SID is taken from a SID string carried by the artifact, for
//! example the Credential Manager vault policy next to the `Protect` folder.
//! Files that reference a domain key are reported for both domain histories
//! because the Windows build that selected the history is not recorded.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Dpapi;
use crate::{HashType, HashValue, Parse, ParseOptions};

const PREFIX: &[u8] = b"$DPAPImk$";
const SID_PREFIX: &[u8] = b"S-1-5-";
const MASTERKEY_HEADER: usize = 128;
const MASTERKEY_BLOB_HEADER: usize = 32;
const MAX_ROUNDS: u32 = 100_000_000;
const CONTEXT_LOCAL: u8 = 1;
const CONTEXT_DOMAIN_HISTORY: u8 = 2;
const CONTEXT_DOMAIN_BACKUP: u8 = 3;

fn terminator(byte: u8) -> bool {
    !byte.is_ascii_graphic()
        || matches!(
            byte,
            b'"' | b'\'' | b',' | b';' | b':' | b')' | b']' | b'}' | b'>' | b'|'
        )
}

fn take_ascii(data: &[u8], start: usize) -> Option<&str> {
    let mut end = start;
    while end < data.len() && !terminator(data[end]) {
        end += 1;
    }
    std::str::from_utf8(&data[start..end])
        .ok()
        .filter(|record| !record.is_empty())
}

fn take_utf16(data: &[u8], start: usize) -> Option<String> {
    let mut text = String::new();
    let mut index = start;
    while index + 1 < data.len() {
        let low = data[index];
        if data[index + 1] != 0 || terminator(low) {
            break;
        }
        text.push(low as char);
        index += 2;
    }
    (!text.is_empty()).then_some(text)
}

fn wide(prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() * 2);
    for byte in prefix {
        out.push(*byte);
        out.push(0);
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// One `$DPAPImk$` record serialized as text in a dump or hive export.
fn records(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();

    let mut index = 0;
    while let Some(position) = find(&data[index..], PREFIX) {
        let start = index + position;
        if let Some(record) = take_ascii(data, start) {
            found.push(record.to_owned());
        }
        index = start + PREFIX.len();
    }

    let needle = wide(PREFIX);
    let mut index = 0;
    while let Some(position) = find(&data[index..], &needle) {
        let start = index + position;
        if let Some(record) = take_utf16(data, start) {
            found.push(record);
        }
        index = start + needle.len();
    }

    found
}

struct MasterKey {
    version: u8,
    cipher: &'static str,
    hash: &'static str,
    rounds: u32,
    salt: [u8; 16],
    contents: Vec<u8>,
}

struct MasterKeyFile {
    domain: bool,
    key: MasterKey,
}

fn utf16_text(field: &[u8]) -> Option<String> {
    if field.len() % 2 != 0 {
        return None;
    }
    let mut text = String::new();
    let mut terminated = false;
    for pair in field.chunks_exact(2) {
        let code = u16::from_le_bytes([pair[0], pair[1]]);
        if code == 0 {
            terminated = true;
            continue;
        }
        if terminated {
            return None;
        }
        let character = char::from_u32(u32::from(code))?;
        if !character.is_ascii_graphic() && character != ' ' {
            return None;
        }
        text.push(character);
    }
    (text.len() >= 8).then_some(text)
}

fn algorithms(hash: u32, cipher: u32) -> Option<(u8, &'static str, &'static str)> {
    match (hash, cipher) {
        (0x8004, 0x6603) => Some((1, "sha1", "des3")),
        (0x800e, 0x6610) => Some((2, "sha512", "aes256")),
        _ => None,
    }
}

fn masterkey_blob(blob: &[u8]) -> Option<MasterKey> {
    if blob.len() < MASTERKEY_BLOB_HEADER {
        return None;
    }
    let rounds = u32_le(blob, 20)?;
    if !(1..=MAX_ROUNDS).contains(&rounds) {
        return None;
    }
    let (version, hash, cipher) = algorithms(u32_le(blob, 24)?, u32_le(blob, 28)?)?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(blob.get(4..20)?);
    let contents = blob.get(MASTERKEY_BLOB_HEADER..)?;
    if contents.len() < 16 || contents.len() % 2 != 0 {
        return None;
    }
    Some(MasterKey {
        version,
        cipher,
        hash,
        rounds,
        salt,
        contents: contents.to_vec(),
    })
}

fn masterkey_file_at(data: &[u8], start: usize) -> Option<MasterKeyFile> {
    let header = data.get(start..start + MASTERKEY_HEADER)?;
    let version = u32_le(header, 0)?;
    if !matches!(version, 1 | 2) {
        return None;
    }
    if header[4..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    utf16_text(&header[12..84])?;
    if header[84..92].iter().any(|byte| *byte != 0) {
        return None;
    }
    let policy = u32_le(header, 92)?;
    if policy == 0 || policy > 3 {
        return None;
    }

    let masterkey_len = u64_le(header, 96)?;
    let backupkey_len = u64_le(header, 104)?;
    let credhist_len = u64_le(header, 112)?;
    let domainkey_len = u64_le(header, 120)?;
    let total = masterkey_len
        .checked_add(backupkey_len)?
        .checked_add(credhist_len)?
        .checked_add(domainkey_len)?;
    let body = data.len().checked_sub(start + MASTERKEY_HEADER)?;
    if total > body as u64 {
        return None;
    }
    if masterkey_len == 0 {
        return None;
    }
    let masterkey_len = usize::try_from(masterkey_len).ok()?;
    let blob = data.get(start + MASTERKEY_HEADER..start + MASTERKEY_HEADER + masterkey_len)?;
    let key = masterkey_blob(blob)?;
    Some(MasterKeyFile {
        domain: domainkey_len > 0,
        key,
    })
}

fn masterkey_files(data: &[u8]) -> Vec<MasterKeyFile> {
    let mut found = Vec::new();
    let mut index = 0;
    while index + MASTERKEY_HEADER <= data.len() {
        let remaining = &data[index..];
        let Some(position) = remaining
            .windows(12)
            .position(|window| matches!(window[0], 1 | 2) && window[1..].iter().all(|b| *b == 0))
        else {
            break;
        };
        let start = index + position;
        if let Some(file) = masterkey_file_at(data, start) {
            found.push(file);
        }
        index = start + 1;
    }
    found
}

fn sid_groups(bytes: &[u8]) -> usize {
    let mut groups = 0;
    let mut digits = 0;
    for byte in bytes {
        if byte.is_ascii_digit() {
            digits += 1;
            if digits > 10 {
                return 0;
            }
        } else if *byte == b'-' {
            if digits == 0 {
                return 0;
            }
            digits = 0;
            groups += 1;
        } else {
            break;
        }
    }
    if digits > 0 {
        groups += 1;
    }
    groups
}

fn ascii_sid(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut end = start + SID_PREFIX.len();
    while end < data.len() && (data[end].is_ascii_digit() || data[end] == b'-') {
        end += 1;
    }
    if end > start + 64 || data[end - 1] == b'-' {
        return None;
    }
    let suffix = &data[start + SID_PREFIX.len()..end];
    (sid_groups(suffix) >= 2)
        .then(|| (String::from_utf8_lossy(&data[start..end]).into_owned(), end))
}

fn utf16_sid(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut text = "S-1-5-".to_owned();
    let mut index = start + SID_PREFIX.len() * 2;
    while index + 1 < data.len() {
        let byte = data[index];
        if data[index + 1] != 0 || !(byte.is_ascii_digit() || byte == b'-') {
            break;
        }
        text.push(byte as char);
        index += 2;
    }
    let suffix = &text[SID_PREFIX.len()..];
    let suffix = suffix.as_bytes();
    if suffix.last() == Some(&b'-') || text.len() > 64 {
        return None;
    }
    (sid_groups(suffix) >= 2).then_some((text, index))
}

fn sids(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();

    let mut index = 0;
    while let Some(position) = find(&data[index..], SID_PREFIX) {
        let start = index + position;
        if let Some((sid, end)) = ascii_sid(data, start) {
            found.push(sid);
            index = end;
        } else {
            index = start + SID_PREFIX.len();
        }
    }

    let needle = wide(SID_PREFIX);
    let mut index = 0;
    while let Some(position) = find(&data[index..], &needle) {
        let start = index + position;
        if let Some((sid, end)) = utf16_sid(data, start) {
            found.push(sid);
            index = end;
        } else {
            index = start + needle.len();
        }
    }

    found
}

fn extract(artifact: &Artifact) -> Result<Vec<Dpapi>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;

    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for record in records(&data) {
        if let Ok(hash) = Dpapi::parse(&record, &opts) {
            hashes.push(hash);
        }
    }

    let files = masterkey_files(&data);
    if !files.is_empty() {
        let mut found = sids(&data);
        found.sort();
        found.dedup();
        let sid = match found.len() {
            1 => found.remove(0),
            0 => {
                return Err(ExtractError::Unsupported(
                    "DPAPI masterkey file does not carry the account SID".to_owned(),
                ));
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "DPAPI artifact contains several account SIDs".to_owned(),
                ));
            }
        };
        for file in files {
            let contexts: &[u8] = if file.domain {
                &[CONTEXT_DOMAIN_HISTORY, CONTEXT_DOMAIN_BACKUP]
            } else {
                &[CONTEXT_LOCAL]
            };
            for context in contexts {
                hashes.push(Dpapi {
                    version: file.key.version,
                    context: *context,
                    sid: sid.clone(),
                    cipher: file.key.cipher.to_owned(),
                    hash: file.key.hash.to_owned(),
                    rounds: file.key.rounds,
                    salt: file.key.salt,
                    contents_size: u32::try_from(file.key.contents.len() * 2)
                        .map_err(|_| ExtractError::Invalid("DPAPI blob is too large".to_owned()))?,
                    contents: file.key.contents.clone(),
                });
            }
        }
    }

    let mut unique: Vec<Dpapi> = Vec::new();
    for hash in hashes {
        if !unique.contains(&hash) {
            unique.push(hash);
        }
    }
    let hashes = unique;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no DPAPI master key records found".to_owned(),
        ));
    }
    Ok(hashes)
}

/// Extractor for DPAPI master key records and masterkey files.
pub struct DpapiExtractor;

impl Extractor for DpapiExtractor {
    fn slug(&self) -> &'static str {
        Dpapi::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match extract(artifact) {
            Ok(_) => Probe::yes("DPAPI master key record"),
            Err(_) => {
                let Ok(data) = artifact.primary().read_all() else {
                    return Probe::No;
                };
                if masterkey_files(&data).is_empty() {
                    Probe::No
                } else {
                    Probe::maybe("DPAPI masterkey file without an account SID")
                }
            }
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
