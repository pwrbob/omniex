//! iTunes and Finder iOS backup `Manifest.plist` keybag extraction.

use byteorder::{BigEndian, ByteOrder};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::ItunesBackup;
use crate::{HashType, HashValue};

pub struct ItunesBackupExtractor;

const TAG_SALT: &[u8] = b"SALT";
const TAG_ITER: &[u8] = b"ITER";
const TAG_WPKY: &[u8] = b"WPKY";
const TAG_DPIC: &[u8] = b"DPIC";
const TAG_DPSL: &[u8] = b"DPSL";
const PLIST_MAGIC: &[u8] = b"bplist00";
const SCAN_CHUNK: usize = 64 * 1024;
const RECORD_WINDOW: usize = 512;
const MAX_SEARCH: usize = 256;

fn read_prefix(source: &dyn ReadAt, offset: u64, len: usize) -> Result<Vec<u8>, ExtractError> {
    let available = source
        .len()
        .saturating_sub(offset)
        .min(u64::try_from(len).unwrap_or(u64::MAX));
    let mut data = vec![0; usize::try_from(available).unwrap_or(0)];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read iTunes backup: {error}")))?;
    Ok(data)
}

fn find_tag(data: &[u8], tag: &[u8], from: usize, limit: usize) -> Option<usize> {
    let end = data.len().min(limit);
    if from >= end {
        return None;
    }
    data[from..end]
        .windows(tag.len())
        .position(|window| window == tag)
        .map(|position| from + position)
}

fn tag_value(data: &[u8], tag: usize, expected: usize) -> Option<&[u8]> {
    let length = BigEndian::read_u32(data.get(tag + 4..tag + 8)?);
    if usize::try_from(length).ok()? != expected {
        return None;
    }
    data.get(tag + 8..tag + 8 + expected)
}

fn parse_record(source: &dyn ReadAt, offset: u64) -> Result<ItunesBackup, ExtractError> {
    let data = read_prefix(source, offset, RECORD_WINDOW)?;
    if data.len() < 8 || &data[..4] != TAG_SALT {
        return Err(ExtractError::Unsupported(
            "not an iTunes backup keybag record".to_owned(),
        ));
    }
    let salt = tag_value(&data, 0, 20)
        .ok_or_else(|| ExtractError::Invalid("iTunes backup SALT is not 20 bytes".to_owned()))?;
    let iter = find_tag(&data, TAG_ITER, 28, MAX_SEARCH)
        .ok_or_else(|| ExtractError::Invalid("iTunes backup ITER is missing".to_owned()))?;
    let iter_value = tag_value(&data, iter, 4)
        .ok_or_else(|| ExtractError::Invalid("iTunes backup ITER is not four bytes".to_owned()))?;
    let iterations = BigEndian::read_u32(iter_value);
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "iTunes backup iteration count is zero".to_owned(),
        ));
    }
    let wpky = find_tag(&data, TAG_WPKY, iter + 8, iter + 8 + MAX_SEARCH)
        .ok_or_else(|| ExtractError::Invalid("iTunes backup WPKY is missing".to_owned()))?;
    let wrapped_key = tag_value(&data, wpky, 40)
        .ok_or_else(|| ExtractError::Invalid("iTunes backup WPKY is not 40 bytes".to_owned()))?;

    let record_end = find_tag(&data, TAG_SALT, TAG_SALT.len(), data.len()).unwrap_or(data.len());
    let dpic = find_tag(&data, TAG_DPIC, 0, record_end);
    let dpsl = dpic.and_then(|dpic| {
        find_tag(&data, TAG_DPSL, dpic + 8, dpic + 8 + MAX_SEARCH).map(|dpsl| (dpic, dpsl))
    });
    let (version, iterations2, extra) = match dpsl {
        Some((dpic, dpsl)) => {
            let dpic_value = tag_value(&data, dpic, 4).ok_or_else(|| {
                ExtractError::Invalid("iTunes backup DPIC is not four bytes".to_owned())
            })?;
            let dpic = BigEndian::read_u32(dpic_value);
            let dpsl = tag_value(&data, dpsl, 20).ok_or_else(|| {
                ExtractError::Invalid("iTunes backup DPSL is not 20 bytes".to_owned())
            })?;
            if dpic == 0 {
                return Err(ExtractError::Invalid(
                    "iTunes backup DPIC is zero".to_owned(),
                ));
            }
            (10, dpic.to_string(), crate::format::hex(dpsl))
        }
        None => (9, String::new(), String::new()),
    };

    Ok(ItunesBackup {
        version,
        wrapped_key: crate::format::hex(wrapped_key),
        iterations,
        salt: crate::format::hex(salt),
        iterations2,
        extra,
    })
}

fn offsets(source: &dyn ReadAt) -> Result<Vec<u64>, ExtractError> {
    let len = source.len();
    let overlap = TAG_SALT.len().saturating_sub(1);
    let mut found = Vec::new();
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
        while index + TAG_SALT.len() <= chunk.len() {
            let Some(position) = chunk[index..]
                .windows(TAG_SALT.len())
                .position(|window| window == TAG_SALT)
            else {
                break;
            };
            found.push(start + u64::try_from(index + position).unwrap_or(0));
            index += position + TAG_SALT.len();
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

fn has_plist_magic(source: &dyn ReadAt) -> bool {
    let mut magic = [0; 8];
    source.read_exact_at(0, &mut magic).is_ok() && magic == PLIST_MAGIC
}

impl Extractor for ItunesBackupExtractor {
    fn slug(&self) -> &'static str {
        ItunesBackup::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let Ok(found) = offsets(source) else {
            return Probe::No;
        };
        if found.is_empty() {
            return Probe::No;
        }
        if !has_plist_magic(source) {
            return Probe::maybe(
                "iTunes backup keybag records are present without a bplist header",
            );
        }
        for offset in &found {
            if parse_record(source, *offset).is_ok() {
                return Probe::yes("iTunes backup binary plist keybag");
            }
        }
        Probe::No
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let source = artifact.primary();
        let found = offsets(source)?;
        if found.is_empty() {
            return Err(ExtractError::Unsupported("not an iTunes backup".to_owned()));
        }
        let mut hashes = Vec::with_capacity(found.len());
        for offset in found {
            let value = parse_record(source, offset)?;
            hashes.push(Box::new(value) as Box<dyn HashValue>);
        }
        Ok(hashes)
    }
}
