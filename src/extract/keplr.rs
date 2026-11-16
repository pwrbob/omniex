//! Keplr browser-extension wallet extraction.

use std::str;

use serde_json::{Map, Value};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Keplr;
use crate::{HashType, HashValue};

pub struct KeplrExtractor;

const BLOCK_SIZE: usize = 32 * 1024;
const HEADER_SIZE: usize = 7;
const MAX_DEPTH: usize = 16;

fn varint(data: &[u8], position: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        let byte = *data.get(*position)?;
        *position += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn log_records(data: &[u8]) -> Result<Vec<Vec<u8>>, ExtractError> {
    let mut records = Vec::new();
    let mut pending: Option<Vec<u8>> = None;
    let mut position = 0;
    while position < data.len() {
        let block_offset = position % BLOCK_SIZE;
        let remaining = BLOCK_SIZE - block_offset;
        if remaining < HEADER_SIZE {
            position += remaining;
            continue;
        }
        let header = data
            .get(position..position + HEADER_SIZE)
            .ok_or_else(|| ExtractError::Invalid("truncated LevelDB log header".to_owned()))?;
        let length = usize::from(u16::from_le_bytes([header[4], header[5]]));
        let kind = header[6];
        position += HEADER_SIZE;
        if length == 0 && kind == 0 {
            position += remaining - HEADER_SIZE;
            continue;
        }
        if length > remaining - HEADER_SIZE {
            return Err(ExtractError::Invalid(
                "invalid LevelDB log record length".to_owned(),
            ));
        }
        let end = position + length;
        let chunk = data
            .get(position..end)
            .ok_or_else(|| ExtractError::Invalid("truncated LevelDB log record".to_owned()))?;
        position = end;
        match kind {
            1 => {
                if pending.is_some() {
                    return Err(ExtractError::Invalid(
                        "unexpected LevelDB full record".to_owned(),
                    ));
                }
                records.push(chunk.to_vec());
            }
            2 => {
                if pending.is_some() {
                    return Err(ExtractError::Invalid(
                        "unexpected LevelDB first record".to_owned(),
                    ));
                }
                pending = Some(chunk.to_vec());
            }
            3 => {
                let buffer = pending.as_mut().ok_or_else(|| {
                    ExtractError::Invalid("unexpected LevelDB middle record".to_owned())
                })?;
                buffer.extend_from_slice(chunk);
            }
            4 => {
                let mut buffer = pending.take().ok_or_else(|| {
                    ExtractError::Invalid("unexpected LevelDB last record".to_owned())
                })?;
                buffer.extend_from_slice(chunk);
                records.push(buffer);
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "invalid LevelDB log record type".to_owned(),
                ));
            }
        }
    }
    if pending.is_some() {
        return Err(ExtractError::Invalid(
            "truncated LevelDB log record".to_owned(),
        ));
    }
    Ok(records)
}

fn write_batch(batch: &[u8], out: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), ExtractError> {
    if batch.len() < 12 {
        return Err(ExtractError::Invalid(
            "truncated LevelDB write batch".to_owned(),
        ));
    }
    let count = u32::from_le_bytes([batch[8], batch[9], batch[10], batch[11]]);
    let mut position = 12;
    for _ in 0..count {
        let tag = *batch.get(position).ok_or_else(|| {
            ExtractError::Invalid("truncated LevelDB write batch entry".to_owned())
        })?;
        position += 1;
        if tag > 1 {
            return Err(ExtractError::Invalid(
                "unsupported LevelDB write batch entry".to_owned(),
            ));
        }
        let key_length = varint(batch, &mut position)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB key length".to_owned()))?;
        let key_length = usize::try_from(key_length)
            .map_err(|_| ExtractError::Invalid("LevelDB key is too large".to_owned()))?;
        let key_end = position + key_length;
        let key = batch
            .get(position..key_end)
            .ok_or_else(|| ExtractError::Invalid("truncated LevelDB key".to_owned()))?;
        position = key_end;
        if tag == 0 {
            continue;
        }
        let value_length = varint(batch, &mut position)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB value length".to_owned()))?;
        let value_length = usize::try_from(value_length)
            .map_err(|_| ExtractError::Invalid("LevelDB value is too large".to_owned()))?;
        let value_end = position + value_length;
        let value = batch
            .get(position..value_end)
            .ok_or_else(|| ExtractError::Invalid("truncated LevelDB value".to_owned()))?;
        position = value_end;
        out.push((key.to_vec(), value.to_vec()));
    }
    Ok(())
}

fn hex(value: &Value, field: &str) -> Result<Vec<u8>, ExtractError> {
    let text = value
        .as_str()
        .ok_or_else(|| ExtractError::Invalid(format!("invalid Keplr `{field}`")))?;
    hex::decode(text).map_err(|_| ExtractError::Invalid(format!("invalid Keplr `{field}` hex")))
}

fn store(map: &Map<String, Value>, hashes: &mut Vec<Keplr>) -> Result<(), ExtractError> {
    let crypto = map
        .get("crypto")
        .and_then(Value::as_object)
        .ok_or_else(|| ExtractError::Invalid("missing Keplr crypto".to_owned()))?;
    if crypto.get("cipher").and_then(Value::as_str) != Some("aes-128-ctr") {
        return Err(ExtractError::Unsupported(
            "unsupported Keplr cipher".to_owned(),
        ));
    }
    if crypto.get("kdf").and_then(Value::as_str) != Some("scrypt") {
        return Err(ExtractError::Unsupported(
            "unsupported Keplr KDF".to_owned(),
        ));
    }
    let params = crypto
        .get("kdfparams")
        .and_then(Value::as_object)
        .ok_or_else(|| ExtractError::Invalid("missing Keplr scrypt parameters".to_owned()))?;
    let parameter = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| ExtractError::Invalid(format!("missing Keplr `{name}` parameter")))
    };
    if parameter("dklen")? != 32
        || parameter("n")? != 131_072
        || parameter("r")? != 8
        || parameter("p")? != 1
    {
        return Err(ExtractError::Unsupported(
            "unsupported Keplr scrypt parameters".to_owned(),
        ));
    }
    let salt = params
        .get("salt")
        .ok_or_else(|| ExtractError::Invalid("missing Keplr salt".to_owned()))
        .and_then(|value| hex(value, "salt"))?;
    if salt.len() != 32 {
        return Err(ExtractError::Invalid(
            "Keplr salt must be 32 bytes".to_owned(),
        ));
    }
    let ciphertext = crypto
        .get("ciphertext")
        .ok_or_else(|| ExtractError::Invalid("missing Keplr ciphertext".to_owned()))
        .and_then(|value| hex(value, "ciphertext"))?;
    if ciphertext.is_empty() || ciphertext.len() > 256 {
        return Err(ExtractError::Unsupported(
            "unsupported Keplr ciphertext size".to_owned(),
        ));
    }
    let mac = crypto
        .get("mac")
        .ok_or_else(|| ExtractError::Invalid("missing Keplr MAC".to_owned()))
        .and_then(|value| hex(value, "mac"))?;
    if mac.len() != 32 {
        return Err(ExtractError::Invalid(
            "Keplr MAC must be 32 bytes".to_owned(),
        ));
    }
    let fields = format!(
        "{}*{}*{}",
        crate::format::hex(salt),
        crate::format::hex(ciphertext),
        crate::format::hex(mac)
    );
    if !hashes.iter().any(|hash| hash.fields == fields) {
        hashes.push(Keplr { fields });
    }
    Ok(())
}

fn collect_json(value: &Value, depth: usize, hashes: &mut Vec<Keplr>) -> Result<(), ExtractError> {
    if depth > MAX_DEPTH {
        return Err(ExtractError::Invalid(
            "Keplr wallet nesting is too deep".to_owned(),
        ));
    }
    match value {
        Value::Object(map) => {
            if map.contains_key("crypto") {
                store(map, hashes)?;
            }
            for value in map.values() {
                collect_json(value, depth + 1, hashes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json(value, depth + 1, hashes)?;
            }
        }
        Value::String(text) if text.starts_with('{') || text.starts_with('[') => {
            let nested: Value = serde_json::from_str(text).map_err(|error| {
                ExtractError::Invalid(format!("invalid nested Keplr JSON: {error}"))
            })?;
            collect_json(&nested, depth + 1, hashes)?;
        }
        _ => {}
    }
    Ok(())
}

fn json_hashes(data: &[u8]) -> Result<Vec<Keplr>, ExtractError> {
    let text = str::from_utf8(data)
        .map_err(|_| ExtractError::Invalid("Keplr wallet is not UTF-8".to_owned()))?;
    let document: Value = serde_json::from_str(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid Keplr JSON: {error}")))?;
    let mut hashes = Vec::new();
    collect_json(&document, 0, &mut hashes)?;
    Ok(hashes)
}

const TABLE_MAGIC: [u8; 8] = [0x57, 0xfb, 0x80, 0x8b, 0x24, 0x75, 0x47, 0xdb];

fn decompress_snappy(data: &[u8]) -> Option<Vec<u8>> {
    let mut position = 0;
    let length = varint(data, &mut position)?;
    let length = usize::try_from(length).ok()?;
    let mut output = Vec::with_capacity(length);
    while position < data.len() {
        let tag = *data.get(position)?;
        position += 1;
        match tag & 0x03 {
            0 => {
                let mut run = usize::from(tag >> 2);
                if run < 60 {
                    run += 1;
                } else {
                    let extra = run - 59;
                    run = 0;
                    for index in 0..extra {
                        run |= usize::from(*data.get(position + index)?) << (8 * index);
                    }
                    position += extra;
                    run += 1;
                }
                output.extend_from_slice(data.get(position..position + run)?);
                position += run;
            }
            kind => {
                let (run, offset) = match kind {
                    1 => {
                        let next = usize::from(*data.get(position)?);
                        position += 1;
                        (
                            usize::from((tag >> 2) & 0x07) + 4,
                            (usize::from(tag & 0xe0) << 3) | next,
                        )
                    }
                    2 => {
                        let offset = usize::from(u16::from_le_bytes([
                            *data.get(position)?,
                            *data.get(position + 1)?,
                        ]));
                        position += 2;
                        (usize::from(tag >> 2) + 1, offset)
                    }
                    _ => {
                        let offset = u32::from_le_bytes([
                            *data.get(position)?,
                            *data.get(position + 1)?,
                            *data.get(position + 2)?,
                            *data.get(position + 3)?,
                        ]);
                        position += 4;
                        (usize::from(tag >> 2) + 1, offset as usize)
                    }
                };
                if offset == 0 || offset > output.len() {
                    return None;
                }
                let start = output.len() - offset;
                for index in 0..run {
                    output.push(output[start + index]);
                }
            }
        }
    }
    (output.len() == length).then_some(output)
}

fn block_contents(data: &[u8], offset: usize, size: usize) -> Option<Vec<u8>> {
    let contents = data.get(offset..offset + size)?;
    match *data.get(offset + size)? {
        0 => Some(contents.to_vec()),
        1 => decompress_snappy(contents),
        _ => None,
    }
}

fn block_entries(block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let restarts = usize::try_from(u32::from_le_bytes([
        *block.get(block.len().checked_sub(4)?)?,
        *block.get(block.len().checked_sub(3)?)?,
        *block.get(block.len().checked_sub(2)?)?,
        *block.get(block.len().checked_sub(1)?)?,
    ]))
    .ok()?;
    let end = block.len().checked_sub(4 + 4 * restarts)?;
    let mut entries = Vec::new();
    let mut position = 0;
    let mut previous: Vec<u8> = Vec::new();
    while position < end {
        let shared = varint(block, &mut position)?;
        let unshared = varint(block, &mut position)?;
        let value_length = varint(block, &mut position)?;
        let shared = usize::try_from(shared).ok()?;
        let unshared = usize::try_from(unshared).ok()?;
        let value_length = usize::try_from(value_length).ok()?;
        if shared > previous.len() {
            return None;
        }
        let mut key = previous[..shared].to_vec();
        key.extend_from_slice(block.get(position..position + unshared)?);
        position += unshared;
        let value = block.get(position..position + value_length)?.to_vec();
        position += value_length;
        previous = key.clone();
        entries.push((key, value));
    }
    Some(entries)
}

fn table_hashes(data: &[u8]) -> Result<Vec<Keplr>, ExtractError> {
    let footer = data
        .get(data.len().saturating_sub(48)..)
        .ok_or_else(|| ExtractError::Invalid("truncated LevelDB table".to_owned()))?;
    if !footer.ends_with(&TABLE_MAGIC) {
        return Err(ExtractError::Invalid(
            "invalid LevelDB table magic".to_owned(),
        ));
    }
    let mut position = 0;
    let mut handle = || {
        let offset = varint(footer, &mut position)?;
        let size = varint(footer, &mut position)?;
        Some((usize::try_from(offset).ok()?, usize::try_from(size).ok()?))
    };
    let (_, _) =
        handle().ok_or_else(|| ExtractError::Invalid("invalid LevelDB footer".to_owned()))?;
    let (index_offset, index_size) =
        handle().ok_or_else(|| ExtractError::Invalid("invalid LevelDB footer".to_owned()))?;
    let index = block_contents(data, index_offset, index_size)
        .ok_or_else(|| ExtractError::Invalid("invalid LevelDB index block".to_owned()))?;
    let entries = block_entries(&index)
        .ok_or_else(|| ExtractError::Invalid("invalid LevelDB index entries".to_owned()))?;
    let mut hashes: Vec<Keplr> = Vec::new();
    for (_, handle) in entries {
        let mut position = 0;
        let offset = varint(&handle, &mut position)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB block handle".to_owned()))?;
        let size = varint(&handle, &mut position)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB block handle".to_owned()))?;
        let offset = usize::try_from(offset)
            .map_err(|_| ExtractError::Invalid("LevelDB block is too large".to_owned()))?;
        let size = usize::try_from(size)
            .map_err(|_| ExtractError::Invalid("LevelDB block is too large".to_owned()))?;
        let block = block_contents(data, offset, size)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB data block".to_owned()))?;
        for (key, value) in block_entries(&block)
            .ok_or_else(|| ExtractError::Invalid("invalid LevelDB data entries".to_owned()))?
        {
            let key = key.get(..key.len().saturating_sub(8)).unwrap_or(&key);
            if key != b"keyring/key-store" && key != b"keyring/key-multi-store" {
                continue;
            }
            for hash in json_hashes(&value)? {
                if !hashes.iter().any(|existing| existing.fields == hash.fields) {
                    hashes.push(hash);
                }
            }
        }
    }
    Ok(hashes)
}

fn leveldb_hashes(data: &[u8]) -> Result<Vec<Keplr>, ExtractError> {
    let mut hashes: Vec<Keplr> = Vec::new();
    let mut entries = Vec::new();
    if data.ends_with(&TABLE_MAGIC) {
        let hashes = table_hashes(data)?;
        if !hashes.is_empty() {
            return Ok(hashes);
        }
    } else {
        for record in log_records(data)? {
            write_batch(&record, &mut entries)?;
        }
    }
    for (key, value) in entries {
        if key != b"keyring/key-store" && key != b"keyring/key-multi-store" {
            continue;
        }
        for hash in json_hashes(&value)? {
            if !hashes.iter().any(|existing| existing.fields == hash.fields) {
                hashes.push(hash);
            }
        }
    }
    Ok(hashes)
}

fn parse(artifact: &Artifact) -> Result<(Vec<Keplr>, bool), ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let trimmed = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|start| &data[start..])
        .unwrap_or(&data);
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        let hashes = json_hashes(trimmed)?;
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no Keplr keyring found".to_owned(),
            ));
        }
        return Ok((hashes, false));
    }
    let hashes = leveldb_hashes(&data)?;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Keplr keyring found".to_owned(),
        ));
    }
    Ok((hashes, true))
}

impl Extractor for KeplrExtractor {
    fn slug(&self) -> &'static str {
        Keplr::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok((_, true)) => Probe::yes("Keplr Chromium LevelDB keyring"),
            Ok((_, false)) => Probe::yes("Keplr keyring JSON"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .0
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
