//! PKZIP ZipCrypto archive extraction.

use std::io;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, OptionSpec, Probe, ReadAt};
use crate::types::{Pkzip, PkzipPayload};
use crate::{HashType, HashValue};

pub struct PkzipExtractor;

const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const CENTRAL_HEADER: &[u8] = b"PK\x01\x02";
const DATA_DESCRIPTOR: &[u8] = b"PK\x07\x08";
const END_OF_CENTRAL: &[u8] = b"PK\x05\x06";
const ZIP64_LOCATOR: &[u8] = b"PK\x06\x07";
const ZIP64_LOCATOR_LENGTH: u64 = 20;
const ZIP64_END_OF_CENTRAL: &[u8] = b"PK\x06\x06";

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_LOCAL_SIZE_UNKNOWN: u16 = 0x0008;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

const AES_METHOD: u16 = 99;
const MAX_CANDIDATES: usize = 8;
const PARTIAL_LENGTH: u64 = 12 + 24;
const MAX_EMBEDDED: u64 = 320 * 1024;
const MAX_EXTRA: u64 = 64 * 1024;
const MAX_CENTRAL_DIRECTORY: u64 = 64 * 1024 * 1024;
const CHUNK: u64 = 64 * 1024;

const OPTIONS: &[OptionSpec] = &[
    OptionSpec::flag(
        "checksum-only",
        "emit only 2-byte checksum records, like zip2john -c",
    ),
    OptionSpec::flag(
        "full-data",
        "embed the full compressed entry above hashcat's 320 KiB limit",
    ),
];

struct Entry {
    version: u16,
    cmp_len: u64,
    decomp_len: u64,
    crc: u32,
    offset: u64,
    offex: u64,
    cmptype: u16,
    checksum: String,
}

fn at(source: &dyn ReadAt, offset: u64, length: u64) -> io::Result<Vec<u8>> {
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "record is too large"))?;
    let mut data = vec![0; length];
    source.read_exact_at(offset, &mut data)?;
    Ok(data)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Finds `needle` from `start`, reading `CHUNK` bytes at a time.
fn find(source: &dyn ReadAt, start: u64, needle: &[u8]) -> io::Result<Option<u64>> {
    let length = source.len();
    if needle.is_empty() || start >= length {
        return Ok(None);
    }
    let overlap = needle.len().saturating_sub(1) as u64;
    let mut window = vec![0; CHUNK as usize];
    let mut offset = start;
    while offset < length {
        let wanted = usize::try_from((length - offset).min(CHUNK)).expect("window fits");
        let read = source.read_at(offset, &mut window[..wanted])?;
        if read == 0 {
            return Ok(None);
        }
        if let Some(position) = window[..read]
            .windows(needle.len())
            .position(|slice| slice == needle)
        {
            return Ok(Some(offset + position as u64));
        }
        offset += (read as u64).saturating_sub(overlap).max(1);
    }
    Ok(None)
}

/// Finds the last occurrence of the end-of-central-directory signature.
fn end_of_central_directory(source: &dyn ReadAt) -> io::Result<Option<u64>> {
    let length = source.len();
    if length < END_OF_CENTRAL.len() as u64 {
        return Ok(None);
    }
    let tail = length.min(END_OF_CENTRAL.len() as u64 + u64::from(u16::MAX));
    let mut data = vec![0; usize::try_from(tail).expect("tail fits")];
    source.read_exact_at(length - tail, &mut data)?;
    Ok(data
        .windows(END_OF_CENTRAL.len())
        .rposition(|slice| slice == END_OF_CENTRAL)
        .map(|position| length - tail + position as u64))
}

struct Directory {
    offset: u64,
    size: u64,
    entries: u64,
}

fn zip64_directory(source: &dyn ReadAt, eocd: u64) -> io::Result<Option<Directory>> {
    if eocd < ZIP64_LOCATOR_LENGTH {
        return Ok(None);
    }
    let locator = eocd - ZIP64_LOCATOR_LENGTH;
    let mut header = [0u8; 20];
    source.read_exact_at(locator, &mut header)?;
    if !header.starts_with(ZIP64_LOCATOR) {
        return Ok(None);
    }
    let record = LittleEndian::read_u64(&header[8..16]);
    if record >= source.len() {
        return Ok(None);
    }
    let mut end = [0u8; 56];
    source.read_exact_at(record, &mut end)?;
    if !end.starts_with(ZIP64_END_OF_CENTRAL) {
        return Ok(None);
    }
    Ok(Some(Directory {
        entries: LittleEndian::read_u64(&end[32..40]),
        size: LittleEndian::read_u64(&end[40..48]),
        offset: LittleEndian::read_u64(&end[48..56]),
    }))
}

fn central_directory(source: &dyn ReadAt) -> io::Result<Option<Directory>> {
    let Some(eocd) = end_of_central_directory(source)? else {
        return Ok(None);
    };
    let mut header = [0u8; 22];
    source.read_exact_at(eocd, &mut header)?;
    if !header.starts_with(END_OF_CENTRAL) {
        return Ok(None);
    }
    let entries = u64::from(LittleEndian::read_u16(&header[10..12]));
    let size = u64::from(LittleEndian::read_u32(&header[12..16]));
    let offset = u64::from(LittleEndian::read_u32(&header[16..20]));

    let directory = if entries == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
        match zip64_directory(source, eocd)? {
            Some(directory) => directory,
            None => Directory {
                offset,
                size,
                entries,
            },
        }
    } else {
        Directory {
            offset,
            size,
            entries,
        }
    };

    if directory.size > MAX_CENTRAL_DIRECTORY || directory.offset >= source.len() {
        return Ok(None);
    }
    let mut signature = [0u8; 4];
    if source
        .read_exact_at(directory.offset, &mut signature)
        .is_err()
        || !signature.starts_with(CENTRAL_HEADER)
    {
        return Ok(None);
    }
    Ok(Some(directory))
}

/// Reads the 64-bit fields of a zip64 extra field, in spec order.
fn zip64_extra(
    extra: &[u8],
    decomp_len: &mut u64,
    cmp_len: &mut u64,
    offset: &mut u64,
    disk: &mut u16,
) {
    let mut cursor = 0;
    while cursor + 4 <= extra.len() {
        let id = LittleEndian::read_u16(&extra[cursor..cursor + 2]);
        let size = usize::from(LittleEndian::read_u16(&extra[cursor + 2..cursor + 4]));
        cursor += 4;
        let Some(data) = extra.get(cursor..cursor + size) else {
            return;
        };
        if id == 0x0001 {
            let mut read = 0;
            if *decomp_len == 0xffff_ffff && read + 8 <= data.len() {
                *decomp_len = LittleEndian::read_u64(&data[read..read + 8]);
                read += 8;
            }
            if *cmp_len == 0xffff_ffff && read + 8 <= data.len() {
                *cmp_len = LittleEndian::read_u64(&data[read..read + 8]);
                read += 8;
            }
            if *offset == 0xffff_ffff && read + 8 <= data.len() {
                *offset = LittleEndian::read_u64(&data[read..read + 8]);
                read += 8;
            }
            if *disk == 0xffff && read + 4 <= data.len() {
                *disk = LittleEndian::read_u16(&data[read..read + 2]);
            }
        }
        cursor += size;
    }
}

fn checksum(crc: u32, lastmod_time: u16, local_size_unknown: bool) -> String {
    if local_size_unknown {
        format!("{:02x}{:02x}", lastmod_time >> 8, lastmod_time & 0xff)
    } else {
        format!("{:02x}{:02x}", (crc >> 24) & 0xff, (crc >> 16) & 0xff)
    }
}

fn supported(version: u16, flags: u16, cmptype: u16) -> bool {
    flags & FLAG_ENCRYPTED != 0
        && cmptype != AES_METHOD
        && flags & FLAG_STRONG_ENCRYPTION == 0
        && matches!(version, 10 | 20 | 45)
        && matches!(cmptype, 0 | 8)
}

struct RawEntry {
    version: u16,
    flags: u16,
    cmptype: u16,
    lastmod_time: u16,
    crc: u32,
    cmp_len: u64,
    decomp_len: u64,
    offset: u64,
}

fn entry(source: &dyn ReadAt, raw: RawEntry) -> io::Result<Entry> {
    let RawEntry {
        version,
        flags,
        cmptype,
        lastmod_time,
        crc,
        cmp_len,
        decomp_len,
        offset,
    } = raw;
    let length = source.len();
    if cmp_len == 0 || cmp_len == 0xffff_ffff || decomp_len < 4 || offset >= length {
        return Err(invalid("empty PKZIP entry"));
    }
    let local = at(source, offset, 30)?;
    if !local.starts_with(LOCAL_HEADER) {
        return Err(invalid("no PKZIP local header at the recorded offset"));
    }
    let name_len = u64::from(LittleEndian::read_u16(&local[26..28]));
    let extra_len = u64::from(LittleEndian::read_u16(&local[28..30]));
    let offex = 30 + name_len + extra_len;
    let data_start = offset
        .checked_add(offex)
        .filter(|start| *start <= length)
        .ok_or_else(|| invalid("truncated PKZIP local header"))?;
    if data_start.saturating_add(cmp_len) > length {
        return Err(invalid("truncated PKZIP entry data"));
    }
    Ok(Entry {
        version,
        cmp_len,
        decomp_len,
        crc,
        offset,
        offex,
        cmptype,
        checksum: checksum(crc, lastmod_time, flags & FLAG_LOCAL_SIZE_UNKNOWN != 0),
    })
}

fn central_entries(source: &dyn ReadAt, directory: &Directory) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let length = source.len();
    let mut position = directory.offset;
    for _ in 0..directory.entries {
        if position + 46 > length {
            break;
        }
        let header = at(source, position, 46)?;
        if !header.starts_with(CENTRAL_HEADER) {
            break;
        }
        let version = LittleEndian::read_u16(&header[6..8]) & 0xff;
        let flags = LittleEndian::read_u16(&header[8..10]);
        let cmptype = LittleEndian::read_u16(&header[10..12]);
        let lastmod_time = LittleEndian::read_u16(&header[12..14]);
        let crc = LittleEndian::read_u32(&header[16..20]);
        let mut cmp_len = u64::from(LittleEndian::read_u32(&header[20..24]));
        let mut decomp_len = u64::from(LittleEndian::read_u32(&header[24..28]));
        let name_len = u64::from(LittleEndian::read_u16(&header[28..30]));
        let extra_len = u64::from(LittleEndian::read_u16(&header[30..32]));
        let comment_len = u64::from(LittleEndian::read_u16(&header[32..34]));
        let mut disk = LittleEndian::read_u16(&header[34..36]);
        let mut offset = u64::from(LittleEndian::read_u32(&header[42..46]));

        position += 46 + name_len + extra_len + comment_len;
        if extra_len > MAX_EXTRA {
            continue;
        }
        if extra_len > 0 {
            let extra = at(source, position - comment_len - extra_len, extra_len)?;
            zip64_extra(
                &extra,
                &mut decomp_len,
                &mut cmp_len,
                &mut offset,
                &mut disk,
            );
        }

        if disk != 0 || !supported(version, flags, cmptype) {
            continue;
        }
        let Ok(entry) = entry(
            source,
            RawEntry {
                version,
                flags,
                cmptype,
                lastmod_time,
                crc,
                cmp_len,
                decomp_len,
                offset,
            },
        ) else {
            continue;
        };
        entries.push(entry);
    }
    Ok(entries)
}

fn descriptor_sizes(source: &dyn ReadAt, start: u64) -> io::Result<Option<(u32, u64, u64)>> {
    let Some(position) = find(source, start, DATA_DESCRIPTOR)? else {
        return Ok(None);
    };
    let mut header = [0u8; 16];
    if source.read_exact_at(position, &mut header).is_err() {
        return Ok(None);
    }
    Ok(Some((
        LittleEndian::read_u32(&header[4..8]),
        u64::from(LittleEndian::read_u32(&header[8..12])),
        u64::from(LittleEndian::read_u32(&header[12..16])),
    )))
}

fn scanned_entries(source: &dyn ReadAt) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let length = source.len();
    let mut search = 0;
    while let Some(position) = find(source, search, LOCAL_HEADER)? {
        search = position + LOCAL_HEADER.len() as u64;
        if position + 30 > length {
            break;
        }
        let header = at(source, position, 30)?;
        let version = LittleEndian::read_u16(&header[4..6]) & 0xff;
        let flags = LittleEndian::read_u16(&header[6..8]);
        let cmptype = LittleEndian::read_u16(&header[8..10]);
        let lastmod_time = LittleEndian::read_u16(&header[10..12]);
        let mut crc = LittleEndian::read_u32(&header[14..18]);
        let mut cmp_len = u64::from(LittleEndian::read_u32(&header[18..22]));
        let mut decomp_len = u64::from(LittleEndian::read_u32(&header[22..26]));
        let name_len = u64::from(LittleEndian::read_u16(&header[26..28]));
        let extra_len = u64::from(LittleEndian::read_u16(&header[28..30]));
        if !supported(version, flags, cmptype) {
            continue;
        }
        if extra_len > 0 && extra_len <= MAX_EXTRA {
            let extra = at(source, position + 30 + name_len, extra_len)?;
            let mut ignored = 0u64;
            let mut disk = 0u16;
            zip64_extra(
                &extra,
                &mut decomp_len,
                &mut cmp_len,
                &mut ignored,
                &mut disk,
            );
        }
        let offex = 30 + name_len + extra_len;
        let Some(data_start) = position.checked_add(offex).filter(|start| *start <= length) else {
            break;
        };
        if cmp_len == 0 || cmp_len == 0xffff_ffff || decomp_len < 4 {
            match descriptor_sizes(source, data_start)? {
                Some((found_crc, found_cmp, found_decomp)) => {
                    if crc == 0 {
                        crc = found_crc;
                    }
                    if cmp_len == 0 || cmp_len == 0xffff_ffff {
                        cmp_len = found_cmp;
                    }
                    if decomp_len < 4 {
                        decomp_len = found_decomp;
                    }
                }
                None => continue,
            }
        }
        if cmp_len == 0 || cmp_len == 0xffff_ffff || decomp_len < 4 {
            continue;
        }
        let Some(data_end) = data_start.checked_add(cmp_len) else {
            continue;
        };
        if data_end > length {
            continue;
        }
        entries.push(Entry {
            version,
            cmp_len,
            decomp_len,
            crc,
            offset: position,
            offex,
            cmptype,
            checksum: checksum(crc, lastmod_time, flags & FLAG_LOCAL_SIZE_UNKNOWN != 0),
        });
    }
    Ok(entries)
}

fn candidates(source: &dyn ReadAt) -> io::Result<Vec<Entry>> {
    let mut entries = match central_directory(source)? {
        Some(directory) => central_entries(source, &directory)?,
        None => Vec::new(),
    };
    if entries.is_empty() {
        entries = scanned_entries(source)?;
    }
    entries.sort_by_key(|entry| entry.cmp_len);
    entries.truncate(MAX_CANDIDATES);
    Ok(entries)
}

fn partial(source: &dyn ReadAt, entry: &Entry) -> Result<Vec<u8>, ExtractError> {
    at(
        source,
        entry.offset + entry.offex,
        entry.cmp_len.min(PARTIAL_LENGTH),
    )
    .map_err(|error| ExtractError::Invalid(format!("cannot read PKZIP entry: {error}")))
}

fn check_bytes(entries: &[Entry]) -> u8 {
    if entries.iter().any(|entry| entry.version >= 20) {
        1
    } else {
        2
    }
}

fn checksum_field(entry: &Entry) -> String {
    format!(
        "1*0*{:x}*{:x}*{}*",
        entry.cmptype,
        entry.cmp_len.min(PARTIAL_LENGTH),
        entry.checksum
    )
}

fn checksum_payload(source: &dyn ReadAt, entries: &[Entry]) -> Result<String, ExtractError> {
    let mut payload = format!("{:x}*{:x}*", entries.len(), check_bytes(entries));
    for entry in entries {
        payload.push_str(&checksum_field(entry));
        payload.push_str(&crate::format::hex(&partial(source, entry)?));
        payload.push('*');
    }
    Ok(payload)
}

/// Payload text up to and including the data record's header.
fn data_head(source: &dyn ReadAt, entries: &[Entry]) -> Result<String, ExtractError> {
    let mut payload = format!("{:x}*{:x}*", entries.len(), check_bytes(entries));
    for entry in entries.iter().skip(1) {
        payload.push_str(&checksum_field(entry));
        payload.push_str(&crate::format::hex(&partial(source, entry)?));
        payload.push('*');
    }
    let entry = &entries[0];
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
    Ok(payload)
}

impl Extractor for PkzipExtractor {
    fn slug(&self) -> &'static str {
        Pkzip::SLUG
    }

    fn options(&self) -> &'static [OptionSpec] {
        OPTIONS
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match candidates(artifact.primary()) {
            Ok(entries) if !entries.is_empty() => Probe::yes("PKZIP ZipCrypto entry"),
            Ok(_) => Probe::No,
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let source = artifact.primary();
        let entries = candidates(source).map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        if entries.is_empty() {
            return Err(ExtractError::Unsupported(
                "no PKZIP ZipCrypto entries found".to_owned(),
            ));
        }

        let checksum_only = artifact.flag("checksum-only");
        let full_data = artifact.flag("full-data");
        if checksum_only && full_data {
            return Err(ExtractError::Invalid(
                "`checksum-only` and `full-data` cannot be combined".to_owned(),
            ));
        }

        let payload = if checksum_only {
            PkzipPayload::Owned(checksum_payload(source, &entries)?)
        } else {
            let smallest = &entries[0];
            if smallest.cmp_len > MAX_EMBEDDED && !full_data {
                return Err(ExtractError::Unsupported(format!(
                    "smallest encrypted entry is {} bytes, above hashcat's 320 KiB data limit; use `--opt checksum-only` for a data-less hash or `--opt full-data` for John",
                    smallest.cmp_len
                )));
            }
            let head = data_head(source, &entries)?;
            if smallest.cmp_len > MAX_EMBEDDED {
                PkzipPayload::streamed(
                    head,
                    smallest.offset + smallest.offex,
                    smallest.cmp_len,
                    Arc::clone(&artifact.primary_shared()),
                )
            } else {
                let data = at(source, smallest.offset + smallest.offex, smallest.cmp_len).map_err(
                    |error| ExtractError::Invalid(format!("cannot read PKZIP entry: {error}")),
                )?;
                let mut payload = head;
                payload.push_str(&crate::format::hex(&data));
                payload.push('*');
                PkzipPayload::Owned(payload)
            }
        };

        let hash = Pkzip {
            version: "pkzip".to_owned(),
            payload,
        };
        Ok(vec![Box::new(hash) as Box<dyn HashValue>])
    }
}
