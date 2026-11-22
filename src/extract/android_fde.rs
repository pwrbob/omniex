//! Android Full Disk Encryption footer extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::AndroidFde;
use crate::{HashType, HashValue};

pub struct AndroidFdeExtractor;

const MAGIC: [u8; 4] = [0xc4, 0xb1, 0xb5, 0xd0];
const PROBE_WINDOW: u64 = 1 << 20;
const FOOTER_SIZE: usize = 100;
const DATA_SAMPLE: usize = 512 * 3;
const SCAN_CHUNK: usize = 64 * 1024;
const SUPPORTED_CIPHER: &str = "aes256/cbc-essiv:sha256";

fn read(source: &dyn ReadAt, offset: u64, len: usize) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; len];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read Android FDE data: {error}")))?;
    Ok(data)
}

fn footer_offsets(source: &dyn ReadAt, from: u64) -> Result<Vec<u64>, ExtractError> {
    let len = source.len();
    let overlap = MAGIC.len().saturating_sub(1);
    let mut found = Vec::new();
    let mut start = from;
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

fn data_sample(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    let source = artifact
        .member("data")
        .unwrap_or_else(|| artifact.primary());
    if source.len() < u64::try_from(DATA_SAMPLE).unwrap_or(u64::MAX) {
        return Err(ExtractError::Invalid(
            "Android FDE data sample is truncated".to_owned(),
        ));
    }
    read(source, 0, DATA_SAMPLE)
}

fn parse_footer(artifact: &Artifact, offset: u64) -> Result<AndroidFde, ExtractError> {
    let source = artifact.primary();
    let footer = read(source, offset, FOOTER_SIZE)?;
    if footer[..4] != MAGIC {
        return Err(ExtractError::Unsupported(
            "not an Android FDE footer".to_owned(),
        ));
    }
    let major = LittleEndian::read_u16(&footer[4..6]);
    let minor = LittleEndian::read_u16(&footer[6..8]);
    let footer_size = LittleEndian::read_u32(&footer[8..12]);
    let keysize = LittleEndian::read_u32(&footer[16..20]);
    let cipher = &footer[36..100];
    let end = cipher
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(cipher.len());
    let cipher = std::str::from_utf8(&cipher[..end])
        .map_err(|_| ExtractError::Invalid("Android FDE cipher name is not ASCII".to_owned()))?;

    if major != 1 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android FDE major version {major}"
        )));
    }
    if minor != 0 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android FDE minor version {minor}"
        )));
    }
    if footer_size < u32::try_from(FOOTER_SIZE).unwrap_or(u32::MAX) || footer_size > 4096 {
        return Err(ExtractError::Invalid(
            "invalid Android FDE footer size".to_owned(),
        ));
    }
    if cipher != SUPPORTED_CIPHER {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android FDE cipher `{cipher}`"
        )));
    }
    if keysize != 16 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Android FDE key size {keysize}"
        )));
    }

    let key_offset = offset
        .checked_add(u64::from(footer_size))
        .ok_or_else(|| ExtractError::Invalid("Android FDE key offset overflow".to_owned()))?;
    let key = read(source, key_offset, usize::try_from(keysize).unwrap_or(0))?;
    let salt_offset = key_offset
        .checked_add(u64::from(keysize) + 32)
        .ok_or_else(|| ExtractError::Invalid("Android FDE salt offset overflow".to_owned()))?;
    let salt: [u8; 16] = read(source, salt_offset, 16)?
        .try_into()
        .expect("sixteen-byte Android FDE salt");
    let data = data_sample(artifact)?;

    Ok(AndroidFde {
        salt,
        digest: key.try_into().expect("sixteen-byte Android FDE key"),
        data,
    })
}

const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::optional(
    "data",
    "data sample when the header does not carry it",
)];

impl Extractor for AndroidFdeExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        AndroidFde::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let from = source.len().saturating_sub(PROBE_WINDOW);
        let Ok(found) = footer_offsets(source, from) else {
            return Probe::No;
        };
        if found.is_empty() {
            return Probe::No;
        }
        for offset in &found {
            if parse_footer(artifact, *offset).is_ok() {
                return Probe::yes("Android FDE encryption footer");
            }
        }
        Probe::maybe("Android FDE magic is present but the footer is unsupported")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let found = footer_offsets(artifact.primary(), 0)?;
        if found.is_empty() {
            return Err(ExtractError::Unsupported(
                "not an Android FDE footer".to_owned(),
            ));
        }
        let mut hashes = Vec::with_capacity(found.len());
        for offset in found {
            hashes.push(Box::new(parse_footer(artifact, offset)?) as Box<dyn HashValue>);
        }
        Ok(hashes)
    }
}
