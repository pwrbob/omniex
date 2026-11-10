//! RAR5 archive header and file encryption extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Rar5;
use crate::{HashType, HashValue};

pub struct Rar5Extractor;

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

const HEAD_MAIN: u8 = 0x01;
const HEAD_FILE: u8 = 0x02;
const HEAD_SERVICE: u8 = 0x03;
const HEAD_CRYPT: u8 = 0x04;

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;

const FHFL_UTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_CRYPT_PSWCHECK: u64 = 0x01;

const SIZE_SALT: usize = 16;
const SIZE_IV: usize = 16;
const SIZE_PSWCHECK: usize = 8;

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn at(data: &'a [u8], position: usize) -> Self {
        Self { data, position }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn byte(&mut self) -> Result<u8, ExtractError> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or_else(|| ExtractError::Invalid("truncated RAR5 header".to_owned()))?;
        self.position += 1;
        Ok(byte)
    }

    fn uint32(&mut self) -> Result<u32, ExtractError> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("four-byte slice"),
        ))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| ExtractError::Invalid("RAR5 header length overflow".to_owned()))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| ExtractError::Invalid("truncated RAR5 header".to_owned()))?;
        self.position = end;
        Ok(bytes)
    }

    fn vint(&mut self) -> Result<u64, ExtractError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ExtractError::Invalid(
            "RAR5 variable integer is too long".to_owned(),
        ))
    }

    fn skip(&mut self, len: usize) -> Result<(), ExtractError> {
        self.bytes(len).map(|_| ())
    }
}

fn crypt_record(
    cursor: &mut Cursor<'_>,
    has_iv: bool,
    has_checksum: bool,
) -> Result<Option<Rar5>, ExtractError> {
    let version = cursor.vint()?;
    if version != 0 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported RAR5 encryption version {version}"
        )));
    }
    let flags = cursor.vint()?;
    let iterations = cursor.byte()?;
    if iterations > 24 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported RAR5 iteration exponent {iterations}"
        )));
    }
    let salt: [u8; SIZE_SALT] = cursor
        .bytes(SIZE_SALT)?
        .try_into()
        .expect("sixteen-byte salt");
    if flags & FHEXTRA_CRYPT_PSWCHECK == 0 {
        return Err(ExtractError::Unsupported(
            "RAR5 encryption without a password check is not supported".to_owned(),
        ));
    }
    let iv = if has_iv {
        cursor.bytes(SIZE_IV)?.try_into().expect("sixteen-byte IV")
    } else {
        [0; SIZE_IV]
    };
    let password_check: [u8; SIZE_PSWCHECK] = cursor
        .bytes(SIZE_PSWCHECK)?
        .try_into()
        .expect("eight-byte password check");
    if has_checksum {
        cursor.uint32()?;
    }
    Ok(Some(Rar5 {
        salt,
        iterations,
        iv,
        password_check,
    }))
}

fn extra_record(extra: &[u8]) -> Result<Option<Rar5>, ExtractError> {
    let mut cursor = Cursor::new(extra);
    while cursor.remaining() > 0 {
        let field_size = cursor.vint()?;
        let field_start = cursor.position;
        let field_type = cursor.vint()?;
        let consumed = cursor.position - field_start;
        let field_size = usize::try_from(field_size)
            .map_err(|_| ExtractError::Invalid("RAR5 extra field is too large".to_owned()))?;
        if field_size < consumed {
            return Err(ExtractError::Invalid(
                "RAR5 extra field is shorter than its type".to_owned(),
            ));
        }
        let payload_len = field_size - consumed;
        let payload = cursor.bytes(payload_len)?;
        if field_type == FHEXTRA_CRYPT {
            let mut field = Cursor::new(payload);
            let hash = crypt_record(&mut field, true, false)?;
            return Ok(hash);
        }
    }
    Ok(None)
}

fn hashes(data: &[u8]) -> Result<Vec<Rar5>, ExtractError> {
    let signature = data
        .windows(SIGNATURE.len())
        .position(|window| window == SIGNATURE)
        .ok_or_else(|| ExtractError::Unsupported("no RAR5 signature found".to_owned()))?;
    let mut cursor = Cursor::at(data, signature + SIGNATURE.len());
    let mut hashes = Vec::new();
    let mut header_crypt: Option<Rar5> = None;

    while cursor.remaining() > 0 {
        let block_start = cursor.position;
        let _header_crc = cursor.uint32()?;
        let header_size = cursor.vint()?;
        let size_bytes = cursor.position - block_start - 4;
        let header_end = cursor
            .position
            .checked_add(
                usize::try_from(header_size)
                    .map_err(|_| ExtractError::Invalid("RAR5 header is too large".to_owned()))?,
            )
            .ok_or_else(|| ExtractError::Invalid("RAR5 header overflow".to_owned()))?;
        if header_end > data.len() {
            return Err(ExtractError::Invalid("truncated RAR5 header".to_owned()));
        }

        let header_type = cursor.byte()?;
        let flags = cursor.vint()?;
        let mut extra_size = 0u64;
        let mut data_size = 0u64;
        if flags & HFL_EXTRA != 0 {
            extra_size = cursor.vint()?;
        }
        if flags & HFL_DATA != 0 {
            data_size = cursor.vint()?;
        }

        match header_type {
            HEAD_CRYPT => {
                header_crypt = crypt_record(&mut cursor, false, true)?;
            }
            HEAD_MAIN => {
                let _archive_flags = cursor.vint()?;
            }
            HEAD_FILE | HEAD_SERVICE => {
                let file_flags = cursor.vint()?;
                let _unpacked_size = cursor.vint()?;
                let _attributes = cursor.vint()?;
                if file_flags & FHFL_UTIME != 0 {
                    cursor.uint32()?;
                }
                if file_flags & FHFL_CRC32 != 0 {
                    cursor.uint32()?;
                }
                let _compression = cursor.vint()?;
                let _host_os = cursor.vint()?;
                let name_size = cursor.vint()?;
                let name_size = usize::try_from(name_size)
                    .map_err(|_| ExtractError::Invalid("RAR5 name is too large".to_owned()))?;
                cursor.skip(name_size)?;
                if extra_size > 0 {
                    let extra_len = usize::try_from(extra_size).map_err(|_| {
                        ExtractError::Invalid("RAR5 extra area is too large".to_owned())
                    })?;
                    let extra = cursor.bytes(extra_len)?;
                    if let Some(hash) = extra_record(extra)? {
                        hashes.push(hash);
                    }
                }
            }
            _ => {}
        }

        let next = header_start_next(block_start, header_size, size_bytes, data_size)?;
        if header_type == HEAD_CRYPT {
            if let Some(mut hash) = header_crypt.take() {
                let iv_start = next;
                let iv_end = iv_start
                    .checked_add(SIZE_IV)
                    .ok_or_else(|| ExtractError::Invalid("RAR5 header IV overflow".to_owned()))?;
                let iv = data.get(iv_start..iv_end).ok_or_else(|| {
                    ExtractError::Invalid("truncated encrypted RAR5 header".to_owned())
                })?;
                hash.iv.copy_from_slice(iv);
                hashes.push(hash);
            }
            break;
        }
        cursor.position = next;
    }
    Ok(hashes)
}

fn header_start_next(
    block_start: usize,
    header_size: u64,
    size_bytes: usize,
    data_size: u64,
) -> Result<usize, ExtractError> {
    let header_size = usize::try_from(header_size)
        .map_err(|_| ExtractError::Invalid("RAR5 header is too large".to_owned()))?;
    let data_size = usize::try_from(data_size)
        .map_err(|_| ExtractError::Invalid("RAR5 data is too large".to_owned()))?;
    block_start
        .checked_add(4)
        .and_then(|value| value.checked_add(size_bytes))
        .and_then(|value| value.checked_add(header_size))
        .and_then(|value| value.checked_add(data_size))
        .ok_or_else(|| ExtractError::Invalid("RAR5 block overflow".to_owned()))
}

impl Extractor for Rar5Extractor {
    fn slug(&self) -> &'static str {
        Rar5::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match hashes(&data) {
            Ok(hashes) if !hashes.is_empty() => Probe::yes("RAR5 encrypted header or file"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = hashes(&data)?;
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no encrypted RAR5 records found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
