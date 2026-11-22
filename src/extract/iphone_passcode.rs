//! iOS backup keybag extraction for iPhone passcode hashes.

use byteorder::{BigEndian, ByteOrder};

use super::{
    Artifact, CompanionSpec, ExtractError, Extracted, Extractor, MemberRole, Probe, ReadAt,
};
use crate::parse;
use crate::types::IphonePasscode;
use crate::{HashType, HashValue};

pub struct IphonePasscodeExtractor;

const KEYBAG_MAGIC: &[u8] = b"VERS";
const PROBE_WINDOW: u64 = 1 << 20;
const SCAN_CHUNK: usize = 64 * 1024;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_RECORDS: usize = 4096;

struct Record {
    tag: [u8; 4],
    data: Vec<u8>,
}

struct Keybag {
    salt: [u8; 20],
    iterations: u32,
    class_keys: Vec<[u8; 40]>,
}

fn read(source: &dyn ReadAt, offset: u64, len: usize) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; len];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read keybag data: {error}")))?;
    Ok(data)
}

fn as_u32(data: &[u8]) -> Option<u32> {
    match data.len() {
        4 => Some(BigEndian::read_u32(data)),
        8 => Some(u32::try_from(BigEndian::read_u64(data)).ok()?),
        _ => None,
    }
}

fn parse_keybag(source: &dyn ReadAt, offset: u64) -> Result<Keybag, ExtractError> {
    let mut records: Vec<Record> = Vec::new();
    let mut position = offset;
    while records.len() < MAX_RECORDS {
        let header = match read(source, position, 8) {
            Ok(header) => header,
            Err(_) if !records.is_empty() => break,
            Err(error) => return Err(error),
        };
        let tag: [u8; 4] = header[..4].try_into().expect("four-byte tag");
        if !tag.iter().all(u8::is_ascii_uppercase) {
            break;
        }
        let length = usize::try_from(BigEndian::read_u32(&header[4..8])).unwrap_or(usize::MAX);
        if length > MAX_PAYLOAD {
            break;
        }
        let Ok(data) = read(source, position + 8, length) else {
            break;
        };
        records.push(Record { tag, data });
        position += u64::try_from(8 + length).unwrap_or(u64::MAX);
    }

    let first = records
        .first()
        .ok_or_else(|| ExtractError::Unsupported("not an iOS keybag".to_owned()))?;
    if first.tag.as_slice() != KEYBAG_MAGIC {
        return Err(ExtractError::Unsupported("not an iOS keybag".to_owned()));
    }
    let version = as_u32(&first.data)
        .ok_or_else(|| ExtractError::Invalid("iOS keybag version is malformed".to_owned()))?;
    if !matches!(version, 3 | 4) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported iOS keybag version {version}"
        )));
    }

    let salt = records
        .iter()
        .find(|record| record.tag.as_slice() == b"SALT")
        .ok_or_else(|| ExtractError::Invalid("iOS keybag SALT is missing".to_owned()))?;
    let salt: [u8; 20] = salt
        .data
        .as_slice()
        .try_into()
        .map_err(|_| ExtractError::Invalid("iOS keybag SALT is not 20 bytes".to_owned()))?;
    let iterations = records
        .iter()
        .find(|record| record.tag.as_slice() == b"ITER")
        .and_then(|record| as_u32(&record.data))
        .ok_or_else(|| ExtractError::Invalid("iOS keybag ITER is missing".to_owned()))?;
    if iterations == 0 {
        return Err(ExtractError::Invalid(
            "iOS keybag iteration count is zero".to_owned(),
        ));
    }

    let mut class_keys = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if record.tag.as_slice() != b"WPKY" || record.data.len() != 40 {
            continue;
        }
        let block_start = records[..index]
            .iter()
            .rposition(|candidate| candidate.tag.as_slice() == b"UUID")
            .map(|uuid| uuid + 1)
            .unwrap_or(0);
        let class = records[block_start..index]
            .iter()
            .find(|candidate| candidate.tag.as_slice() == b"CLAS")
            .and_then(|candidate| as_u32(&candidate.data));
        let wrap = records[block_start..index]
            .iter()
            .find(|candidate| candidate.tag.as_slice() == b"WRAP")
            .and_then(|candidate| as_u32(&candidate.data));
        if matches!(class, Some(1 | 33)) && wrap == Some(3) {
            let key: [u8; 40] = record.data.as_slice().try_into().expect("forty-byte WPKY");
            if !class_keys.contains(&key) {
                class_keys.push(key);
            }
        }
    }
    if class_keys.is_empty() {
        return Err(ExtractError::Invalid(
            "iOS keybag has no class 1 or 33 wrapped key".to_owned(),
        ));
    }
    Ok(Keybag {
        salt,
        iterations,
        class_keys,
    })
}

fn offsets(source: &dyn ReadAt, from: u64, len: u64) -> Result<Vec<u64>, ExtractError> {
    let overlap = KEYBAG_MAGIC.len().saturating_sub(1);
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
        while index + KEYBAG_MAGIC.len() <= chunk.len() {
            let Some(position) = chunk[index..]
                .windows(KEYBAG_MAGIC.len())
                .position(|window| window == KEYBAG_MAGIC)
            else {
                break;
            };
            found.push(start + u64::try_from(index + position).unwrap_or(0));
            index += position + KEYBAG_MAGIC.len();
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

fn uid_key(artifact: &Artifact) -> Result<[u8; 16], ExtractError> {
    for member in artifact.members() {
        let MemberRole::Named(name) = &member.role else {
            continue;
        };
        let normalized: String = name
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        if normalized != "uidkey" {
            continue;
        }
        let length = usize::try_from(member.source.len().min(128)).unwrap_or(0);
        let mut data = vec![0; length];
        member
            .source
            .read_exact_at(0, &mut data)
            .map_err(|error| ExtractError::Invalid(format!("cannot read UID key: {error}")))?;
        while data.last().is_some_and(u8::is_ascii_whitespace) {
            data.pop();
        }
        if data.len() == 16 {
            return Ok(data.try_into().expect("sixteen-byte UID key"));
        }
        let text = std::str::from_utf8(&data)
            .map_err(|_| ExtractError::Invalid("UID key is not ASCII hex".to_owned()))?;
        let bytes = parse::decode_hex(text, 0)
            .map_err(|_| ExtractError::Invalid("UID key is not valid hex".to_owned()))?;
        return bytes
            .try_into()
            .map_err(|_| ExtractError::Invalid("UID key is not 16 bytes".to_owned()));
    }
    Err(ExtractError::Unsupported(
        "iOS keybag does not contain the device UID key; attach a `uid-key` companion".to_owned(),
    ))
}

const COMPANIONS: &[CompanionSpec] = &[CompanionSpec::optional(
    "uid-key",
    "device UID key when it is not stored in the keybag; `uid_key` and `uidkey` are accepted",
)];

impl Extractor for IphonePasscodeExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        IphonePasscode::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let len = source.len();
        let mut found = Vec::new();
        for (from, end) in [
            (0, len.min(PROBE_WINDOW)),
            (len.saturating_sub(PROBE_WINDOW), len),
        ] {
            let Ok(mut offsets) = offsets(source, from, end) else {
                return Probe::No;
            };
            found.append(&mut offsets);
        }
        found.sort_unstable();
        found.dedup();
        if found.is_empty() {
            return Probe::No;
        }
        for offset in &found {
            if parse_keybag(source, *offset).is_ok() {
                return Probe::yes("iOS keybag with a wrapped class key");
            }
        }
        Probe::maybe("iOS keybag header is present but no class key is extractable")
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let source = artifact.primary();
        let found = offsets(source, 0, source.len())?;
        if found.is_empty() {
            return Err(ExtractError::Unsupported("not an iOS keybag".to_owned()));
        }
        let mut keybags = Vec::new();
        let mut last_error = None;
        for offset in found {
            match parse_keybag(source, offset) {
                Ok(keybag) => keybags.push(keybag),
                Err(error) => last_error = Some(error),
            }
        }
        if keybags.is_empty() {
            return Err(last_error
                .unwrap_or_else(|| ExtractError::Unsupported("not an iOS keybag".to_owned())));
        }
        let uid_key = uid_key(artifact)?;
        let mut hashes = Vec::new();
        for keybag in keybags {
            for class_key in keybag.class_keys {
                hashes.push(Box::new(IphonePasscode {
                    uid_key,
                    salt: keybag.salt,
                    iterations: keybag.iterations,
                    class_key,
                }) as Box<dyn HashValue>);
            }
        }
        Ok(hashes)
    }
}
