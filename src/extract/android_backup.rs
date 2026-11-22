//! Android Backup (`.ab`) encryption header extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::parse;
use crate::types::AndroidBackup;
use crate::{HashType, HashValue};

pub struct AndroidBackupExtractor;

const MAGIC: &[u8] = b"ANDROID BACKUP\n";
const PROBE_WINDOW: u64 = 1 << 20;
const HEADER_LIMIT: usize = 8192;
const SCAN_CHUNK: usize = 64 * 1024;

fn read_prefix(source: &dyn ReadAt, offset: u64, len: usize) -> Result<Vec<u8>, ExtractError> {
    let available = source
        .len()
        .saturating_sub(offset)
        .min(u64::try_from(len).unwrap_or(u64::MAX));
    let mut data = vec![0; usize::try_from(available).unwrap_or(0)];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Android backup: {error}")))?;
    Ok(data)
}

fn header_lines(data: &[u8]) -> Vec<&[u8]> {
    data.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect()
}

fn parse_header_at(source: &dyn ReadAt, offset: u64) -> Result<AndroidBackup, ExtractError> {
    let data = read_prefix(source, offset, HEADER_LIMIT)?;
    let lines = header_lines(&data);
    if lines.first().copied() != Some(MAGIC.strip_suffix(b"\n").unwrap_or(MAGIC)) {
        return Err(ExtractError::Unsupported(
            "not an Android backup header".to_owned(),
        ));
    }
    if lines.len() < 9 {
        return Err(ExtractError::Invalid(
            "truncated Android backup header".to_owned(),
        ));
    }
    let number = |index: usize, name: &str| -> Result<u32, ExtractError> {
        let text = std::str::from_utf8(lines[index])
            .map_err(|_| ExtractError::Invalid(format!("Android backup {name} is not ASCII")))?;
        text.parse::<u32>()
            .map_err(|_| ExtractError::Invalid(format!("invalid Android backup {name}")))
    };
    let version = u8::try_from(number(1, "version")?)
        .map_err(|_| ExtractError::Unsupported("Android backup version is too large".to_owned()))?;
    if !(1..=5).contains(&version) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android backup version {version}"
        )));
    }
    let compressed = number(2, "compression flag")?;
    if compressed > 1 {
        return Err(ExtractError::Invalid(
            "invalid Android backup compression flag".to_owned(),
        ));
    }
    let algorithm = std::str::from_utf8(lines[3])
        .map_err(|_| ExtractError::Invalid("Android backup algorithm is not ASCII".to_owned()))?;
    if algorithm != "AES-256" {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android backup encryption algorithm `{algorithm}`"
        )));
    }
    let decode = |index: usize, name: &str| -> Result<Vec<u8>, ExtractError> {
        let text = std::str::from_utf8(lines[index])
            .map_err(|_| ExtractError::Invalid(format!("Android backup {name} is not ASCII")))?;
        parse::decode_hex(text, 0)
            .map_err(|_| ExtractError::Invalid(format!("invalid Android backup {name}")))
    };
    let user_salt = decode(4, "user salt")?;
    let checksum_salt = decode(5, "checksum salt")?;
    let iterations = number(6, "iteration count")?;
    let user_iv = decode(7, "user iv")?;
    let master_key_blob = decode(8, "master key blob")?;
    Ok(AndroidBackup {
        version,
        cipher: 0,
        iterations,
        user_salt: user_salt.try_into().map_err(|_| {
            ExtractError::Invalid("Android backup user salt is not 64 bytes".to_owned())
        })?,
        checksum_salt: checksum_salt.try_into().map_err(|_| {
            ExtractError::Invalid("Android backup checksum salt is not 64 bytes".to_owned())
        })?,
        user_iv: user_iv.try_into().map_err(|_| {
            ExtractError::Invalid("Android backup user iv is not 16 bytes".to_owned())
        })?,
        master_key_blob: master_key_blob.try_into().map_err(|_| {
            ExtractError::Invalid("Android backup master key blob is not 96 bytes".to_owned())
        })?,
    })
}

fn offsets(artifact: &Artifact, window: u64) -> Result<Vec<u64>, ExtractError> {
    let source = artifact.primary();
    let len = source.len().min(window);
    let mut found = Vec::new();
    let overlap = MAGIC.len().saturating_sub(1);
    let mut start = 0u64;
    while start < len {
        let read_len = usize::try_from(len - start)
            .unwrap_or(usize::MAX)
            .min(SCAN_CHUNK);
        let mut chunk = vec![0; read_len];
        let read = source
            .read_at(start, &mut chunk)
            .map_err(|error| ExtractError::Invalid(format!("cannot scan artifact: {error}")))?;
        chunk.truncate(read);
        let mut index = 0;
        while index + MAGIC.len() <= chunk.len() {
            let Some(position) = chunk[index..]
                .windows(MAGIC.len())
                .position(|window| window == MAGIC)
            else {
                break;
            };
            found.push(start + u64::try_from(index + position).unwrap_or(0));
            index += position + MAGIC.len();
        }
        if read <= overlap {
            break;
        }
        start += u64::try_from(read - overlap).unwrap_or(1);
    }
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

impl Extractor for AndroidBackupExtractor {
    fn slug(&self) -> &'static str {
        AndroidBackup::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let mut magic = [0u8; 15];
        if artifact.primary().read_exact_at(0, &mut magic).is_err() || magic != MAGIC {
            return Probe::No;
        }
        let Ok(found) = offsets(artifact, PROBE_WINDOW) else {
            return Probe::No;
        };
        if found.is_empty() {
            return Probe::No;
        }
        for offset in &found {
            if parse_header_at(artifact.primary(), *offset).is_ok() {
                return Probe::yes("Android Backup encrypted header");
            }
        }
        Probe::maybe("Android Backup magic is present but the header is unsupported")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let found = offsets(artifact, u64::MAX)?;
        if found.is_empty() {
            return Err(ExtractError::Unsupported(
                "not an Android backup".to_owned(),
            ));
        }
        let mut hashes = Vec::with_capacity(found.len());
        for offset in found {
            let value = parse_header_at(artifact.primary(), offset)?;
            hashes.push(Box::new(value) as Box<dyn HashValue>);
        }
        Ok(hashes)
    }
}
