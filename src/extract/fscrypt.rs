//! Google fscrypt protector extraction.

use omniex::extract::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use omniex::types::Fscrypt;
use omniex::{HashType, HashValue};

pub struct FscryptExtractor;

const MAX_PROTECTOR: u64 = 64 * 1024;

#[derive(Clone, Copy)]
enum Value<'a> {
    Integer(u64),
    Bytes(&'a [u8]),
}

fn varint(data: &[u8], position: &mut usize) -> Result<u64, ExtractError> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(*position)
            .ok_or_else(|| ExtractError::Invalid("truncated fscrypt protobuf".to_owned()))?;
        *position += 1;
        value |= u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| ExtractError::Invalid("fscrypt protobuf is too large".to_owned()))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(ExtractError::Invalid(
                "invalid fscrypt protobuf varint".to_owned(),
            ));
        }
    }
}

fn fields(data: &[u8]) -> Result<Vec<(u64, Value<'_>)>, ExtractError> {
    let mut result = Vec::new();
    let mut position = 0;
    while position < data.len() {
        let key = varint(data, &mut position)?;
        let number = key >> 3;
        let wire = key & 7;
        let value = match wire {
            0 => Value::Integer(varint(data, &mut position)?),
            2 => {
                let length = usize::try_from(varint(data, &mut position)?)
                    .map_err(|_| ExtractError::Invalid("fscrypt field is too large".to_owned()))?;
                let start = position;
                let end = start
                    .checked_add(length)
                    .ok_or_else(|| ExtractError::Invalid("fscrypt field overflows".to_owned()))?;
                let bytes = data.get(start..end).ok_or_else(|| {
                    ExtractError::Invalid("truncated fscrypt protobuf".to_owned())
                })?;
                position = end;
                Value::Bytes(bytes)
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "unsupported fscrypt protobuf wire type".to_owned(),
                ));
            }
        };
        result.push((number, value));
    }
    Ok(result)
}

fn integer(fields: &[(u64, Value<'_>)], number: u64) -> Option<u64> {
    fields.iter().find_map(|(field, value)| match value {
        Value::Integer(integer) if *field == number => Some(*integer),
        _ => None,
    })
}

fn bytes<'a>(fields: &[(u64, Value<'a>)], number: u64) -> Option<&'a [u8]> {
    fields.iter().find_map(|(field, value)| match value {
        Value::Bytes(bytes) if *field == number => Some(*bytes),
        _ => None,
    })
}

fn hash(data: &[u8]) -> Result<Option<Fscrypt>, ExtractError> {
    let top = fields(data)?;
    let Some(source) = integer(&top, 2) else {
        return Ok(None);
    };
    if source == 3 {
        return Ok(None);
    }
    let Some(costs) = bytes(&top, 4) else {
        return Ok(None);
    };
    let Some(salt) = bytes(&top, 5) else {
        return Ok(None);
    };
    let Some(wrapped) = bytes(&top, 7) else {
        return Ok(None);
    };
    let costs = fields(costs)?;
    let wrapped = fields(wrapped)?;
    let (Some(time), Some(memory), Some(parallelism)) =
        (integer(&costs, 2), integer(&costs, 3), integer(&costs, 4))
    else {
        return Ok(None);
    };
    let (Some(iv), Some(encrypted), Some(mac)) =
        (bytes(&wrapped, 1), bytes(&wrapped, 2), bytes(&wrapped, 3))
    else {
        return Ok(None);
    };
    if salt.len() != 16 || iv.len() != 16 || encrypted.len() != 32 || mac.len() != 32 {
        return Ok(None);
    }
    let parallelism = if integer(&costs, 5).unwrap_or(0) != 0 {
        parallelism
    } else {
        parallelism & 0xff
    };
    let time = u32::try_from(time)
        .map_err(|_| ExtractError::Invalid("fscrypt time cost is too large".to_owned()))?;
    let memory = u32::try_from(memory)
        .map_err(|_| ExtractError::Invalid("fscrypt memory cost is too large".to_owned()))?;
    let parallelism = u32::try_from(parallelism)
        .map_err(|_| ExtractError::Invalid("fscrypt parallelism is too large".to_owned()))?;
    Ok(Some(Fscrypt {
        data: format!(
            "{time}*{memory}*{parallelism}*{}*{}*{}*{}",
            omniex::format::hex(salt),
            omniex::format::hex(iv),
            omniex::format::hex(encrypted),
            omniex::format::hex(mac)
        ),
    }))
}

fn extract_all(artifact: &Artifact) -> Result<Vec<Fscrypt>, ExtractError> {
    let mut hashes = Vec::new();
    for member in artifact.members() {
        let source: &dyn ReadAt = &*member.source;
        if source.is_empty() || source.len() > MAX_PROTECTOR {
            continue;
        }
        let data = source
            .read_all()
            .map_err(|error| ExtractError::Invalid(format!("cannot read {error}")))?;
        match hash(&data) {
            Ok(Some(hash)) => hashes.push(hash),
            Ok(None) => {}
            Err(ExtractError::Invalid(_)) => {}
            Err(error) => return Err(error),
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no fscrypt passphrase protector found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for FscryptExtractor {
    fn slug(&self) -> &'static str {
        Fscrypt::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match extract_all(artifact) {
            Ok(_) => Probe::maybe("fscrypt ProtectorData protobuf"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(extract_all(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
