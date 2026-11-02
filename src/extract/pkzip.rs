//! PKZIP ZipCrypto archive extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pkzip;
use crate::{HashType, HashValue};

pub struct PkzipExtractor;

const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const DATA_DESCRIPTOR: &[u8] = b"PK\x07\x08";

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_LOCAL_SIZE_UNKNOWN: u16 = 0x0008;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

const AES_METHOD: u16 = 99;
const MAX_CANDIDATES: usize = 8;
const PARTIAL_LENGTH: usize = 12 + 24;

struct Entry {
    version: u16,
    cmp_len: usize,
    decomp_len: u32,
    crc: u32,
    offset: usize,
    offex: usize,
    cmptype: u16,
    checksum: String,
    data: Vec<u8>,
}

fn find_header(data: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    data.get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}

fn scan_descriptor(data: &[u8], start: usize, zip64: bool) -> Option<(u32, u64, u64)> {
    let position = start
        + data.get(start..)?.windows(4).position(|window| {
            window == b"PK\x01\x02" || window == b"PK\x03\x04" || window == b"PK\x07\x08"
        })?;
    if data.get(position..)?.starts_with(DATA_DESCRIPTOR) {
        let mut cursor = position + 4;
        let crc = LittleEndian::read_u32(data.get(cursor..cursor + 4)?);
        cursor += 4;
        let (cmp_len, decomp_len) = if zip64 {
            let cmp = LittleEndian::read_u64(data.get(cursor..cursor + 8)?);
            cursor += 8;
            let decomp = LittleEndian::read_u64(data.get(cursor..cursor + 8)?);
            (cmp, decomp)
        } else {
            let cmp = u64::from(LittleEndian::read_u32(data.get(cursor..cursor + 4)?));
            cursor += 4;
            let decomp = u64::from(LittleEndian::read_u32(data.get(cursor..cursor + 4)?));
            (cmp, decomp)
        };
        let _ = cursor;
        return Some((crc, cmp_len, decomp_len));
    }
    if position < 16 {
        return None;
    }
    let base = position - 16;
    let crc = LittleEndian::read_u32(data.get(base..base + 4)?);
    let cmp_len = u64::from(LittleEndian::read_u32(data.get(base + 4..base + 8)?));
    let decomp_len = u64::from(LittleEndian::read_u32(data.get(base + 8..base + 12)?));
    Some((crc, cmp_len, decomp_len))
}

fn parse_entry(data: &[u8], start: usize) -> Result<Option<Entry>, ExtractError> {
    let Some(header) = data.get(start..start + 30) else {
        return Err(ExtractError::Invalid(
            "truncated PKZIP local header".to_owned(),
        ));
    };
    let version = LittleEndian::read_u16(&header[4..6]) & 0xff;
    let flags = LittleEndian::read_u16(&header[6..8]);
    let cmptype = LittleEndian::read_u16(&header[8..10]);
    let lastmod_time = LittleEndian::read_u16(&header[10..12]);
    let mut crc = LittleEndian::read_u32(&header[14..18]);
    let mut cmp_len = LittleEndian::read_u32(&header[18..22]);
    let mut decomp_len = LittleEndian::read_u32(&header[22..26]);
    let name_len = LittleEndian::read_u16(&header[26..28]) as usize;
    let extra_len = LittleEndian::read_u16(&header[28..30]) as usize;

    if flags & FLAG_ENCRYPTED == 0 {
        return Ok(None);
    }
    if cmptype == AES_METHOD
        || flags & FLAG_STRONG_ENCRYPTION != 0
        || version == 51
        || version == 52
        || version >= 61
    {
        return Ok(None);
    }
    if !matches!(version, 10 | 20 | 45) || !matches!(cmptype, 0 | 8) {
        return Ok(None);
    }

    let offex = 30 + name_len + extra_len;
    let data_start = start
        .checked_add(offex)
        .filter(|offset| *offset <= data.len())
        .ok_or_else(|| ExtractError::Invalid("truncated PKZIP local header".to_owned()))?;

    if flags & FLAG_LOCAL_SIZE_UNKNOWN != 0 {
        if let Some((found_crc, found_cmp, found_decomp)) = scan_descriptor(data, data_start, false)
        {
            if crc == 0 {
                crc = found_crc;
            }
            if cmp_len == 0 {
                cmp_len = u32::try_from(found_cmp).unwrap_or(u32::MAX);
            }
            if decomp_len == 0 {
                decomp_len = u32::try_from(found_decomp).unwrap_or(u32::MAX);
            }
        }
    }

    if cmp_len == 0 || cmp_len == u32::MAX {
        return Ok(None);
    }
    if decomp_len < 4 {
        return Ok(None);
    }
    let cmp_len = cmp_len as usize;
    let end = data_start
        .checked_add(cmp_len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| ExtractError::Invalid("truncated PKZIP entry data".to_owned()))?;

    let checksum = if flags & FLAG_LOCAL_SIZE_UNKNOWN != 0 {
        format!("{:02x}{:02x}", lastmod_time >> 8, lastmod_time & 0xff)
    } else {
        format!("{:02x}{:02x}", (crc >> 24) & 0xff, (crc >> 16) & 0xff)
    };

    Ok(Some(Entry {
        version,
        cmp_len,
        decomp_len,
        crc,
        offset: start,
        offex,
        cmptype,
        checksum,
        data: data[data_start..end].to_vec(),
    }))
}

fn entries(data: &[u8]) -> Result<Vec<Entry>, ExtractError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(start) = find_header(data, offset, LOCAL_HEADER) {
        if let Some(entry) = parse_entry(data, start)? {
            entries.push(entry);
        }
        offset = start + LOCAL_HEADER.len();
    }
    entries.sort_by_key(|entry| entry.cmp_len);
    entries.truncate(MAX_CANDIDATES);
    Ok(entries)
}

fn payload(entries: &[Entry]) -> String {
    let check_bytes = if entries.iter().any(|entry| entry.version >= 20) {
        1
    } else {
        2
    };
    let mut payload = format!("{:x}*{:x}*", entries.len(), check_bytes);
    for entry in entries.iter().skip(1) {
        let partial = entry.cmp_len.min(PARTIAL_LENGTH);
        payload.push_str(&format!(
            "1*0*{:x}*{:x}*{}*",
            entry.cmptype, partial, entry.checksum
        ));
        payload.push_str(&crate::format::hex(&entry.data[..partial]));
        payload.push('*');
    }
    if let Some(entry) = entries.first() {
        payload.push_str(&format!(
            "2*0*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{}*",
            entry.cmp_len,
            entry.decomp_len,
            entry.crc,
            entry.offset,
            entry.offex,
            entry.cmptype,
            entry.cmp_len,
            entry.checksum
        ));
        payload.push_str(&crate::format::hex(&entry.data));
        payload.push('*');
    }
    payload
}

impl Extractor for PkzipExtractor {
    fn slug(&self) -> &'static str {
        Pkzip::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match entries(&data) {
            Ok(entries) if !entries.is_empty() => Probe::yes("PKZIP ZipCrypto entry"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let entries = entries(&data)?;
        if entries.is_empty() {
            return Err(ExtractError::Unsupported(
                "no PKZIP ZipCrypto entries found".to_owned(),
            ));
        }
        let hash = Pkzip {
            version: "pkzip".to_owned(),
            payload: payload(&entries),
        };
        Ok(vec![Box::new(hash) as Box<dyn HashValue>])
    }
}
