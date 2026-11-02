//! macOS local account SHA1 password plist extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::MacosSha1;
use crate::{HashType, HashValue};

pub(crate) mod plist {
    //! Minimal binary property list reader shared by the macOS extractors.

    use super::ExtractError;

    const HEADER: &[u8] = b"bplist00";
    const TRAILER: usize = 32;

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub(crate) enum Value {
        Null,
        Bool(bool),
        Int(i64),
        Real(f64),
        Date(f64),
        Data(Vec<u8>),
        String(String),
        Array(Vec<Value>),
        Dict(Vec<(String, Value)>),
        Uid(u64),
    }

    impl Value {
        pub(crate) fn get(&self, key: &str) -> Option<&Self> {
            match self {
                Self::Dict(entries) => entries
                    .iter()
                    .find_map(|(name, value)| (name == key).then_some(value)),
                _ => None,
            }
        }

        pub(crate) fn as_data(&self) -> Option<&[u8]> {
            match self {
                Self::Data(value) => Some(value),
                _ => None,
            }
        }

        pub(crate) fn as_array(&self) -> Option<&[Self]> {
            match self {
                Self::Array(values) => Some(values),
                _ => None,
            }
        }

        pub(crate) fn as_int(&self) -> Option<i64> {
            match self {
                Self::Int(value) => Some(*value),
                _ => None,
            }
        }
    }

    fn be_u64(data: &[u8], offset: usize) -> Option<u64> {
        let bytes = data.get(offset..offset + 8)?;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }

    fn invalid(message: &str) -> ExtractError {
        ExtractError::Invalid(message.to_owned())
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Value, ExtractError> {
        if data.get(..HEADER.len()) != Some(HEADER) {
            return Err(ExtractError::Unsupported(
                "not a binary property list".to_owned(),
            ));
        }
        if data.len() < HEADER.len() + TRAILER {
            return Err(invalid("truncated binary property list"));
        }
        let trailer = &data[data.len() - TRAILER..];
        let offset_size = usize::from(trailer[6]);
        let ref_size = usize::from(trailer[7]);
        let count = be_u64(trailer, 8).ok_or_else(|| invalid("truncated plist trailer"))?;
        let top = be_u64(trailer, 16).ok_or_else(|| invalid("truncated plist trailer"))?;
        let table = be_u64(trailer, 24).ok_or_else(|| invalid("truncated plist trailer"))?;
        if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 {
            return Err(invalid("invalid plist reference width"));
        }
        if count == 0 || top >= count {
            return Err(invalid("invalid plist object table"));
        }
        let table =
            usize::try_from(table).map_err(|_| invalid("plist offset table is too large"))?;
        let table_len = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(offset_size))
            .ok_or_else(|| invalid("plist offset table is too large"))?;
        let body_end = data.len() - TRAILER;
        if table < HEADER.len()
            || table
                .checked_add(table_len)
                .is_none_or(|end| end > body_end)
        {
            return Err(invalid("plist offset table is out of bounds"));
        }
        let reader = Reader {
            data: &data[..body_end],
            offsets: &data[table..table + table_len],
            offset_size,
            ref_size,
            count,
        };
        reader.object(top, 0)
    }

    pub(crate) fn shadow_hash_dictionary(data: &[u8]) -> Result<Value, ExtractError> {
        let root = parse(data)?;
        let blobs = root
            .get("ShadowHashData")
            .and_then(Value::as_array)
            .ok_or_else(|| ExtractError::Unsupported("plist has no ShadowHashData".to_owned()))?;
        let blob = blobs
            .first()
            .and_then(Value::as_data)
            .ok_or_else(|| invalid("ShadowHashData is not a data value"))?;
        parse(blob)
    }

    struct Reader<'a> {
        data: &'a [u8],
        offsets: &'a [u8],
        offset_size: usize,
        ref_size: usize,
        count: u64,
    }

    impl Reader<'_> {
        fn offset(&self, index: u64) -> Result<usize, ExtractError> {
            if index >= self.count {
                return Err(invalid("plist object reference is out of range"));
            }
            let index = usize::try_from(index).map_err(|_| invalid("plist index is too large"))?;
            let start = index * self.offset_size;
            let Some(bytes) = self.offsets.get(start..start + self.offset_size) else {
                return Err(invalid("truncated plist offset table"));
            };
            let mut value = 0usize;
            for byte in bytes {
                value = (value << 8) | usize::from(*byte);
            }
            Ok(value)
        }

        fn read(&self, offset: usize, length: usize) -> Result<&[u8], ExtractError> {
            offset
                .checked_add(length)
                .and_then(|end| self.data.get(offset..end))
                .ok_or_else(|| invalid("truncated plist object"))
        }

        fn reference(&self, offset: usize) -> Result<u64, ExtractError> {
            let bytes = self.read(offset, self.ref_size)?;
            let mut value = 0u64;
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
            Ok(value)
        }

        fn length(&self, low: u8, cursor: &mut usize) -> Result<usize, ExtractError> {
            if low != 0x0f {
                return Ok(usize::from(low));
            }
            let marker = *self
                .data
                .get(*cursor)
                .ok_or_else(|| invalid("truncated plist length"))?;
            if marker >> 4 != 0x1 {
                return Err(invalid("plist length is not an integer"));
            }
            let size = 1usize << (marker & 0x0f);
            if size > 8 {
                return Err(invalid("plist length integer is too wide"));
            }
            let bytes = self.read(*cursor + 1, size)?;
            *cursor += 1 + size;
            let mut value = 0usize;
            for byte in bytes {
                value = value
                    .checked_shl(8)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| invalid("plist length is too large"))?;
            }
            Ok(value)
        }

        fn object(&self, index: u64, depth: usize) -> Result<Value, ExtractError> {
            if depth > 64 {
                return Err(invalid("plist is nested too deeply"));
            }
            let offset = self.offset(index)?;
            let marker = *self
                .data
                .get(offset)
                .ok_or_else(|| invalid("truncated plist object"))?;
            let high = marker >> 4;
            let low = marker & 0x0f;
            let mut cursor = offset + 1;
            match high {
                0x0 => match low {
                    0x8 => Ok(Value::Bool(false)),
                    0x9 => Ok(Value::Bool(true)),
                    _ => Ok(Value::Null),
                },
                0x1 => {
                    let size = 1usize << low;
                    if size > 8 {
                        return Err(invalid("plist integer is too wide"));
                    }
                    let bytes = self.read(cursor, size)?;
                    let mut value = 0u64;
                    for byte in bytes {
                        value = (value << 8) | u64::from(*byte);
                    }
                    let value = if size == 8 {
                        i64::from_be_bytes(value.to_be_bytes())
                    } else {
                        i64::try_from(value).map_err(|_| invalid("plist integer is too large"))?
                    };
                    Ok(Value::Int(value))
                }
                0x2 => {
                    let size = 1usize << low;
                    let bytes = self.read(cursor, size)?;
                    let value = match size {
                        4 => f64::from(f32::from_be_bytes(
                            bytes
                                .try_into()
                                .map_err(|_| invalid("truncated plist real"))?,
                        )),
                        8 => f64::from_be_bytes(
                            bytes
                                .try_into()
                                .map_err(|_| invalid("truncated plist real"))?,
                        ),
                        _ => return Err(invalid("unsupported plist real width")),
                    };
                    Ok(Value::Real(value))
                }
                0x3 => {
                    let bytes = self.read(cursor, 8)?;
                    let value = f64::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|_| invalid("truncated plist date"))?,
                    );
                    Ok(Value::Date(value))
                }
                0x4 => {
                    let length = self.length(low, &mut cursor)?;
                    Ok(Value::Data(self.read(cursor, length)?.to_vec()))
                }
                0x5 => {
                    let length = self.length(low, &mut cursor)?;
                    let bytes = self.read(cursor, length)?;
                    let text = String::from_utf8(bytes.to_vec())
                        .map_err(|_| invalid("plist string is not UTF-8"))?;
                    Ok(Value::String(text))
                }
                0x6 => {
                    let length = self.length(low, &mut cursor)?;
                    let bytes = self.read(
                        cursor,
                        length
                            .checked_mul(2)
                            .ok_or_else(|| invalid("plist UTF-16 string is too large"))?,
                    )?;
                    let units: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                        .collect();
                    let text = String::from_utf16(&units)
                        .map_err(|_| invalid("plist UTF-16 string is invalid"))?;
                    Ok(Value::String(text))
                }
                0x8 => {
                    let size = usize::from(low) + 1;
                    if size > 8 {
                        return Err(invalid("plist UID is too wide"));
                    }
                    let bytes = self.read(cursor, size)?;
                    let mut value = 0u64;
                    for byte in bytes {
                        value = (value << 8) | u64::from(*byte);
                    }
                    Ok(Value::Uid(value))
                }
                0xa | 0xc => self.array(low, &mut cursor, depth),
                0xd => self.dictionary(low, &mut cursor, depth),
                _ => Err(invalid("unsupported plist object type")),
            }
        }

        fn array(&self, low: u8, cursor: &mut usize, depth: usize) -> Result<Value, ExtractError> {
            let count = self.length(low, cursor)?;
            let mut values = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let reference = self.reference(*cursor)?;
                *cursor += self.ref_size;
                values.push(self.object(reference, depth + 1)?);
            }
            Ok(Value::Array(values))
        }

        fn dictionary(
            &self,
            low: u8,
            cursor: &mut usize,
            depth: usize,
        ) -> Result<Value, ExtractError> {
            let count = self.length(low, cursor)?;
            let mut keys = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let reference = self.reference(*cursor)?;
                *cursor += self.ref_size;
                match self.object(reference, depth + 1)? {
                    Value::String(key) => keys.push(key),
                    _ => return Err(invalid("plist dictionary key is not a string")),
                }
            }
            let mut entries = Vec::with_capacity(count.min(1024));
            for key in keys {
                let reference = self.reference(*cursor)?;
                *cursor += self.ref_size;
                entries.push((key, self.object(reference, depth + 1)?));
            }
            Ok(Value::Dict(entries))
        }
    }
}

const SHADOW_HASH_LENGTH: usize = 24;

fn parse(artifact: &Artifact) -> Result<MacosSha1, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let shadow = plist::shadow_hash_dictionary(&data)?;
    let blob = shadow
        .get("SALTED-SHA1")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| ExtractError::Unsupported("no SALTED-SHA1 shadow hash".to_owned()))?;
    if blob.len() != SHADOW_HASH_LENGTH {
        return Err(ExtractError::Invalid(
            "macOS SHA1 shadow hash has the wrong length".to_owned(),
        ));
    }
    Ok(MacosSha1 {
        salt: blob[..4].try_into().expect("four-byte salt"),
        digest: blob[4..].try_into().expect("twenty-byte digest"),
    })
}

pub struct MacosSha1Extractor;

impl Extractor for MacosSha1Extractor {
    fn slug(&self) -> &'static str {
        MacosSha1::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("macOS SHA1 shadow hash"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
