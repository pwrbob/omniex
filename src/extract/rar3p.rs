//! RAR3 packed-file extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Rar3p;
use crate::{HashType, HashValue};

pub struct Rar3pExtractor;

const MARKER: &[u8] = b"Rar!\x1a\x07\x00";
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const END_HEAD: u8 = 0x7b;

const FLAG_ENCRYPTED: u16 = 0x0004;
const FLAG_SOLID: u16 = 0x0010;
const FLAG_LARGE: u16 = 0x0100;
const FLAG_SALT: u16 = 0x0400;
const FLAG_ADD_SIZE: u16 = 0x8000;
const FLAG_HEADER_ENCRYPTED: u16 = 0x0080;

const BASE_FILE_HEAD_SIZE: usize = 32;
const PACK_SIZE_MAX: u32 = 327_680;
const UNPACK_SIZE_MAX: u32 = 655_360;

fn locate_markers(data: &[u8]) -> Vec<usize> {
    let mut markers = Vec::new();
    let mut offset = 0;
    while let Some(position) = data[offset..]
        .windows(MARKER.len())
        .position(|window| window == MARKER)
    {
        let start = offset + position;
        markers.push(start);
        offset = start + MARKER.len();
    }
    markers
}

fn parse_file(data: &[u8], offset: usize, head_size: usize, flags: u16) -> Option<Rar3p> {
    if head_size < BASE_FILE_HEAD_SIZE || offset + BASE_FILE_HEAD_SIZE > data.len() {
        return None;
    }
    if flags & FLAG_ENCRYPTED == 0 || flags & FLAG_SALT == 0 || flags & FLAG_SOLID != 0 {
        return None;
    }
    if (flags & 0x00e0) >> 5 == 7 {
        return None;
    }
    if data[offset + 24] < 29 {
        return None;
    }
    let method = data[offset + 25];
    if !matches!(method, 0x30..=0x35) {
        return None;
    }

    let pack_size = LittleEndian::read_u32(&data[offset + 7..offset + 11]);
    let unpack_size = LittleEndian::read_u32(&data[offset + 11..offset + 15]);
    let mut position = offset + BASE_FILE_HEAD_SIZE;
    if flags & FLAG_LARGE != 0 {
        if position + 8 > data.len() {
            return None;
        }
        if LittleEndian::read_u32(&data[position..position + 4]) != 0
            || LittleEndian::read_u32(&data[position + 4..position + 8]) != 0
        {
            return None;
        }
        position += 8;
    }
    let name_size = LittleEndian::read_u16(&data[offset + 26..offset + 28]) as usize;
    position = position.checked_add(name_size)?;
    if position + 8 > offset + head_size || position + 8 > data.len() {
        return None;
    }
    let mut salt = [0; 8];
    salt.copy_from_slice(&data[position..position + 8]);

    let data_offset = offset.checked_add(head_size)?;
    let end = data_offset.checked_add(pack_size as usize)?;
    if end > data.len() {
        return None;
    }
    if pack_size == 0 || pack_size > PACK_SIZE_MAX || pack_size % 16 != 0 {
        return None;
    }
    if unpack_size == 0 || unpack_size > UNPACK_SIZE_MAX {
        return None;
    }

    let mut crc = [0; 4];
    crc.copy_from_slice(&data[offset + 16..offset + 20]);
    Some(Rar3p {
        header_type: "1".to_owned(),
        salt,
        crc,
        pack_size,
        unpack_size,
        method: 1,
        data: data[data_offset..end].to_vec(),
        check: [method],
    })
}

fn parse(data: &[u8]) -> Result<Vec<Rar3p>, ExtractError> {
    let markers = locate_markers(data);
    if markers.is_empty() {
        return Err(ExtractError::Unsupported(
            "no RAR3 marker block found".to_owned(),
        ));
    }
    let mut hashes = Vec::new();
    for marker in markers {
        let mut offset = marker + MARKER.len();
        let Some(main) = data.get(offset..offset + 7) else {
            return Err(ExtractError::Invalid(
                "truncated RAR3 archive header".to_owned(),
            ));
        };
        if main[2] != MAIN_HEAD {
            return Err(ExtractError::Invalid(
                "invalid RAR3 archive header".to_owned(),
            ));
        }
        let main_flags = LittleEndian::read_u16(&main[3..5]);
        if main_flags & FLAG_HEADER_ENCRYPTED != 0 {
            return Err(ExtractError::Unsupported(
                "RAR3 archive uses header encryption".to_owned(),
            ));
        }
        let main_size = LittleEndian::read_u16(&main[5..7]) as usize;
        if main_size < 7 {
            return Err(ExtractError::Invalid(
                "invalid RAR3 archive header size".to_owned(),
            ));
        }
        offset = offset
            .checked_add(main_size)
            .filter(|offset| *offset <= data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated RAR3 archive header".to_owned()))?;

        while offset < data.len() {
            let Some(block) = data.get(offset..offset + 7) else {
                return Err(ExtractError::Invalid(
                    "truncated RAR3 block header".to_owned(),
                ));
            };
            let head_type = block[2];
            let flags = LittleEndian::read_u16(&block[3..5]);
            let head_size = LittleEndian::read_u16(&block[5..7]) as usize;
            if head_size < 7 {
                return Err(ExtractError::Invalid(
                    "invalid RAR3 block header size".to_owned(),
                ));
            }
            if head_type == END_HEAD {
                break;
            }
            let mut block_size = head_size;
            if head_type == FILE_HEAD {
                if offset + BASE_FILE_HEAD_SIZE > data.len() {
                    return Err(ExtractError::Invalid(
                        "truncated RAR3 file header".to_owned(),
                    ));
                }
                let mut pack_size = u64::from(LittleEndian::read_u32(&data[offset + 7..offset + 11]));
                if flags & FLAG_LARGE != 0 {
                    let Some(high) = data.get(offset + 32..offset + 36) else {
                        return Err(ExtractError::Invalid(
                            "truncated RAR3 file header".to_owned(),
                        ));
                    };
                    pack_size += u64::from(LittleEndian::read_u32(high)) << 32;
                }
                let pack_size = usize::try_from(pack_size)
                    .map_err(|_| ExtractError::Invalid("invalid RAR3 file size".to_owned()))?;
                block_size = block_size
                    .checked_add(pack_size)
                    .ok_or_else(|| ExtractError::Invalid("invalid RAR3 file size".to_owned()))?;
                if let Some(hash) = parse_file(data, offset, head_size, flags) {
                    hashes.push(hash);
                }
            } else if flags & FLAG_ADD_SIZE != 0 {
                let Some(size) = data.get(offset + 7..offset + 11) else {
                    return Err(ExtractError::Invalid(
                        "truncated RAR3 block size".to_owned(),
                    ));
                };
                block_size = block_size
                    .checked_add(LittleEndian::read_u32(size) as usize)
                    .ok_or_else(|| ExtractError::Invalid("invalid RAR3 block size".to_owned()))?;
            }
            if block_size < 7 {
                return Err(ExtractError::Invalid("invalid RAR3 block size".to_owned()));
            }
            offset = match offset.checked_add(block_size) {
                Some(next) if next <= data.len() => next,
                _ => return Err(ExtractError::Invalid("truncated RAR3 archive".to_owned())),
            };
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no encrypted RAR3 files found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for Rar3pExtractor {
    fn slug(&self) -> &'static str {
        Rar3p::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match parse(&data) {
            Ok(_) => Probe::yes("RAR3 encrypted file header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        Ok(parse(&data)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
