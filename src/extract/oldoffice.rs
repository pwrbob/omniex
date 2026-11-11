//! MS Office 97-2003 document encryption extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::OldOffice;
use crate::{HashType, HashValue};

pub struct OldOfficeExtractor;

const CFB_SIGNATURE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE_SECTOR: u32 = 0xffff_ffff;
const FILEPASS: u16 = 0x2f;

struct DirEntry {
    name: String,
    kind: u8,
    start: u32,
    size: u64,
}

/// Minimal Compound File Binary reader.
pub(crate) struct Cfb {
    data: Vec<u8>,
    sector_size: usize,
    mini_sector_size: usize,
    mini_cutoff: u64,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    entries: Vec<DirEntry>,
    mini_stream: Vec<u8>,
}

impl Cfb {
    /// Parses an OLE compound file.
    pub(crate) fn parse(data: Vec<u8>) -> Result<Self, ExtractError> {
        if data.len() < 512 || &data[..8] != CFB_SIGNATURE {
            return Err(ExtractError::Unsupported(
                "not an OLE compound file".to_owned(),
            ));
        }
        let sector_shift = LittleEndian::read_u16(&data[0x1e..0x20]);
        let mini_shift = LittleEndian::read_u16(&data[0x20..0x22]);
        if !(7..=12).contains(&sector_shift) || !(4..=sector_shift).contains(&mini_shift) {
            return Err(ExtractError::Invalid(
                "OLE file has invalid sector sizes".to_owned(),
            ));
        }
        let sector_size = 1usize << sector_shift;
        let mini_sector_size = 1usize << mini_shift;
        let num_fat = LittleEndian::read_u32(&data[0x2c..0x30]);
        let first_dir = LittleEndian::read_u32(&data[0x30..0x34]);
        let mini_cutoff = u64::from(LittleEndian::read_u32(&data[0x38..0x3c]));
        let first_minifat = LittleEndian::read_u32(&data[0x3c..0x40]);
        let num_minifat = LittleEndian::read_u32(&data[0x40..0x44]);
        let first_difat = LittleEndian::read_u32(&data[0x44..0x48]);
        let num_difat = LittleEndian::read_u32(&data[0x48..0x4c]);

        let mut fat_sectors: Vec<u32> = (0..109)
            .map(|index| LittleEndian::read_u32(&data[0x4c + index * 4..0x50 + index * 4]))
            .filter(|sector| *sector != FREE_SECTOR)
            .collect();
        let mut difat = first_difat;
        let entries_per_sector = sector_size / 4;
        for _ in 0..num_difat {
            if difat == FREE_SECTOR || difat == END_OF_CHAIN {
                break;
            }
            let sector = sector_offset(difat, sector_size)?;
            let bytes = data
                .get(sector..sector + sector_size)
                .ok_or_else(|| ExtractError::Invalid("truncated OLE DIFAT sector".to_owned()))?;
            for index in 0..entries_per_sector - 1 {
                let value = LittleEndian::read_u32(&bytes[index * 4..index * 4 + 4]);
                if value != FREE_SECTOR {
                    fat_sectors.push(value);
                }
            }
            difat = LittleEndian::read_u32(&bytes[(entries_per_sector - 1) * 4..]);
        }
        fat_sectors.truncate(usize::try_from(num_fat).unwrap_or(fat_sectors.len()));

        let mut fat = Vec::new();
        for sector in fat_sectors {
            let offset = sector_offset(sector, sector_size)?;
            let bytes = data
                .get(offset..offset + sector_size)
                .ok_or_else(|| ExtractError::Invalid("truncated OLE FAT sector".to_owned()))?;
            for index in 0..entries_per_sector {
                fat.push(LittleEndian::read_u32(&bytes[index * 4..index * 4 + 4]));
            }
        }

        let directory = read_chain(&data, &fat, first_dir, sector_size)?;
        let mut entries = Vec::new();
        for chunk in directory.chunks(128) {
            if chunk.len() < 128 {
                break;
            }
            let name_len = usize::from(LittleEndian::read_u16(&chunk[64..66]));
            let kind = chunk[66];
            if !(2..=64).contains(&name_len) || kind == 0 {
                continue;
            }
            let name = decode_utf16(&chunk[..name_len - 2]);
            let start = LittleEndian::read_u32(&chunk[116..120]);
            let size = LittleEndian::read_u64(&chunk[120..128]);
            entries.push(DirEntry {
                name,
                kind,
                start,
                size,
            });
        }

        let root = entries
            .iter()
            .find(|entry| entry.kind == 5)
            .ok_or_else(|| ExtractError::Invalid("OLE file has no root entry".to_owned()))?;
        let mut mini_stream = read_chain(&data, &fat, root.start, sector_size)?;
        let root_size = usize::try_from(root.size).unwrap_or(mini_stream.len());
        mini_stream.truncate(root_size.min(mini_stream.len()));

        let minifat_data = if first_minifat == FREE_SECTOR || first_minifat == END_OF_CHAIN {
            Vec::new()
        } else {
            read_chain(&data, &fat, first_minifat, sector_size)?
        };
        let mut mini_fat = Vec::new();
        for chunk in minifat_data.chunks(4) {
            if chunk.len() < 4 {
                break;
            }
            mini_fat.push(LittleEndian::read_u32(chunk));
        }
        let _ = num_minifat;

        Ok(Self {
            data,
            sector_size,
            mini_sector_size,
            mini_cutoff,
            fat,
            mini_fat,
            entries,
            mini_stream,
        })
    }

    /// Returns whether a stream with this name exists.
    pub(crate) fn has_stream(&self, name: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.kind == 2 && entry.name.eq_ignore_ascii_case(name))
    }

    /// Reads a stream by name.
    pub(crate) fn stream(&self, name: &str) -> Option<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.kind == 2 && entry.name.eq_ignore_ascii_case(name))?;
        let size = usize::try_from(entry.size).unwrap_or(usize::MAX);
        if entry.size < self.mini_cutoff {
            let data = read_chain_at(
                &self.mini_stream,
                &self.mini_fat,
                entry.start,
                self.mini_sector_size,
                0,
            )
            .ok()?;
            let mut data = data;
            data.truncate(size.min(data.len()));
            Some(data)
        } else {
            let data = read_chain(&self.data, &self.fat, entry.start, self.sector_size).ok()?;
            let mut data = data;
            data.truncate(size.min(data.len()));
            Some(data)
        }
    }
}

fn sector_offset(sector: u32, sector_size: usize) -> Result<usize, ExtractError> {
    usize::try_from(sector)
        .ok()
        .and_then(|sector| (sector + 1).checked_mul(sector_size))
        .ok_or_else(|| ExtractError::Invalid("OLE sector offset overflow".to_owned()))
}

fn read_chain(
    data: &[u8],
    table: &[u32],
    start: u32,
    sector_size: usize,
) -> Result<Vec<u8>, ExtractError> {
    read_chain_at(data, table, start, sector_size, sector_size)
}

fn read_chain_at(
    data: &[u8],
    table: &[u32],
    start: u32,
    sector_size: usize,
    base: usize,
) -> Result<Vec<u8>, ExtractError> {
    if start == FREE_SECTOR || start == END_OF_CHAIN {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut sector = start;
    let limit = table.len().max(1);
    for _ in 0..limit {
        let offset = usize::try_from(sector)
            .ok()
            .and_then(|sector| sector.checked_mul(sector_size))
            .and_then(|offset| offset.checked_add(base))
            .ok_or_else(|| ExtractError::Invalid("OLE sector offset overflow".to_owned()))?;
        let bytes = data
            .get(offset..offset + sector_size)
            .ok_or_else(|| ExtractError::Invalid("truncated OLE sector".to_owned()))?;
        output.extend_from_slice(bytes);
        let next = *table
            .get(usize::try_from(sector).unwrap_or(usize::MAX))
            .ok_or_else(|| ExtractError::Invalid("OLE chain leaves the table".to_owned()))?;
        if next == END_OF_CHAIN || next == FREE_SECTOR {
            return Ok(output);
        }
        sector = next;
    }
    Err(ExtractError::Invalid(
        "OLE sector chain is cyclic".to_owned(),
    ))
}

fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(LittleEndian::read_u16)
        .collect();
    String::from_utf16_lossy(&units)
}

struct Verifier {
    version: u8,
    salt: [u8; 16],
    verifier: [u8; 16],
    hash: Vec<u8>,
    second_block: Vec<u8>,
}

fn read_verifier(cursor: &mut &[u8], version: u8) -> Result<Verifier, ExtractError> {
    let salt_size = take_u32(cursor)?;
    if salt_size != 16 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported Office salt size {salt_size}"
        )));
    }
    let salt: [u8; 16] = take(cursor, 16)?.try_into().expect("sixteen-byte salt");
    let verifier: [u8; 16] = take(cursor, 16)?.try_into().expect("sixteen-byte verifier");
    let hash_size = take_u32(cursor)? as usize;
    let hash = take(cursor, hash_size)?.to_vec();
    Ok(Verifier {
        version,
        salt,
        verifier,
        hash,
        second_block: Vec::new(),
    })
}

fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], ExtractError> {
    if cursor.len() < len {
        return Err(ExtractError::Invalid(
            "truncated Office encryption header".to_owned(),
        ));
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

fn take_u16(cursor: &mut &[u8]) -> Result<u16, ExtractError> {
    Ok(LittleEndian::read_u16(take(cursor, 2)?))
}

fn take_u32(cursor: &mut &[u8]) -> Result<u32, ExtractError> {
    Ok(LittleEndian::read_u32(take(cursor, 4)?))
}

fn cryptoapi_verifier(data: &[u8], kind: &str) -> Result<Verifier, ExtractError> {
    let mut cursor = data;
    let _flags = take_u32(&mut cursor)?;
    let mut header_len = take_u32(&mut cursor)?;
    let _skip_flags = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _size_extra = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _alg_id = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _alg_hash = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let key_size = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _provider = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _unused = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    let _unused = take_u32(&mut cursor)?;
    header_len = header_len.saturating_sub(4);
    if kind == "Excel" {
        let _unused = take_u32(&mut cursor)?;
        header_len = header_len.saturating_sub(4);
    }
    let _csp = take(&mut cursor, header_len as usize)?;
    let version = match key_size {
        0 | 40 => 3,
        128 | 256 => 4,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported {kind} key size {other}"
            )));
        }
    };
    read_verifier(&mut cursor, version)
}

fn word_table(cfb: &Cfb) -> Result<&'static str, ExtractError> {
    let document = cfb
        .stream("WordDocument")
        .ok_or_else(|| ExtractError::Unsupported("missing WordDocument stream".to_owned()))?;
    if document.len() < 12 || document[..2] != [0xec, 0xa5] {
        return Err(ExtractError::Invalid("invalid Word FIB header".to_owned()));
    }
    let flags = document[11];
    let encrypted = flags & 1 != 0;
    if !encrypted {
        return Err(ExtractError::Unsupported(
            "Word document is not encrypted; no password hash to extract".to_owned(),
        ));
    }
    Ok(if flags & 2 != 0 { "1Table" } else { "0Table" })
}

fn word_verifier(cfb: &Cfb) -> Result<Verifier, ExtractError> {
    let table = word_table(cfb)?;
    let stream = cfb
        .stream(table)
        .ok_or_else(|| ExtractError::Unsupported(format!("missing {table} stream")))?;
    let mut cursor = stream.as_slice();
    let major = take_u16(&mut cursor)?;
    let minor = take_u16(&mut cursor)?;
    if major == 1 || minor == 1 {
        let salt: [u8; 16] = take(&mut cursor, 16)?
            .try_into()
            .expect("sixteen-byte salt");
        let verifier: [u8; 16] = take(&mut cursor, 16)?
            .try_into()
            .expect("sixteen-byte verifier");
        let hash = take(&mut cursor, 16)?.to_vec();
        return Ok(Verifier {
            version: 1,
            salt,
            verifier,
            hash,
            second_block: Vec::new(),
        });
    }
    if major < 2 || minor != 2 {
        return Err(ExtractError::Unsupported(
            "unsupported Word encryption, likely XOR obfuscation; no password hash to extract"
                .to_owned(),
        ));
    }
    let mut verifier = cryptoapi_verifier(&stream[4..], "Word")?;
    if verifier.version == 3 {
        verifier.second_block = stream.get(512..544).map_or_else(Vec::new, <[u8]>::to_vec);
    }
    Ok(verifier)
}

fn excel_verifier(cfb: &Cfb) -> Result<Verifier, ExtractError> {
    excel_verifier_stream(cfb, "Workbook")
}

fn excel_verifier_stream(cfb: &Cfb, name: &str) -> Result<Verifier, ExtractError> {
    let stream = cfb
        .stream(name)
        .ok_or_else(|| ExtractError::Unsupported(format!("missing {name} stream")))?;
    let mut position = 0usize;
    while position + 4 <= stream.len() {
        let kind = LittleEndian::read_u16(&stream[position..position + 2]);
        let length = LittleEndian::read_u16(&stream[position + 2..position + 4]) as usize;
        let start = position + 4;
        let end = start
            .checked_add(length)
            .ok_or_else(|| ExtractError::Invalid("Excel record length overflow".to_owned()))?;
        let data = stream
            .get(start..end)
            .ok_or_else(|| ExtractError::Invalid("truncated Excel FILEPASS record".to_owned()))?;
        position = end;
        if kind != FILEPASS {
            continue;
        }
        if data.len() == 4 {
            return Err(ExtractError::Unsupported(
                "Excel 95 XOR obfuscation is reversible; no password hash to extract".to_owned(),
            ));
        }
        if data.starts_with(&[0, 0]) {
            return Err(ExtractError::Unsupported(
                "Excel XOR obfuscation is reversible; no password hash to extract".to_owned(),
            ));
        }
        if data.starts_with(&[1, 0, 1, 0, 1, 0]) {
            let payload = &data[6..];
            if payload.len() < 48 {
                return Err(ExtractError::Invalid(
                    "truncated Excel RC4 verifier".to_owned(),
                ));
            }
            return Ok(Verifier {
                version: 0,
                salt: payload[..16].try_into().expect("sixteen-byte salt"),
                verifier: payload[16..32].try_into().expect("sixteen-byte verifier"),
                hash: payload[32..48].to_vec(),
                second_block: Vec::new(),
            });
        }
        if data.starts_with(&[1, 0, 2, 0])
            || data.starts_with(&[1, 0, 3, 0])
            || data.starts_with(&[1, 0, 4, 0])
        {
            let mut verifier = cryptoapi_verifier(&data[6..], "Excel")?;
            if verifier.version == 3 {
                verifier.second_block =
                    stream.get(1024..1056).map_or_else(Vec::new, <[u8]>::to_vec);
            }
            return Ok(verifier);
        }
    }
    Err(ExtractError::Unsupported(
        "Excel workbook is not encrypted; no password hash to extract".to_owned(),
    ))
}

fn power_point_verifier(cfb: &Cfb) -> Result<Verifier, ExtractError> {
    let current_user = cfb
        .stream("Current User")
        .ok_or_else(|| ExtractError::Unsupported("missing Current User stream".to_owned()))?;
    if current_user.len() < 20 {
        return Err(ExtractError::Invalid(
            "truncated PowerPoint Current User stream".to_owned(),
        ));
    }
    let offset_to_current_edit = LittleEndian::read_u32(&current_user[16..20]) as usize;
    let document = cfb
        .stream("PowerPoint Document")
        .ok_or_else(|| ExtractError::Unsupported("missing PowerPoint Document".to_owned()))?;
    if offset_to_current_edit + 8 > document.len() {
        return Err(ExtractError::Invalid(
            "PowerPoint edit offset is out of range".to_owned(),
        ));
    }
    let rec_len = LittleEndian::read_u32(&document[offset_to_current_edit + 4..]) as usize;
    if rec_len != 32 || LittleEndian::read_u16(&document[offset_to_current_edit + 2..]) != 0x0ff5 {
        return Err(ExtractError::Unsupported(
            "PowerPoint document is not encrypted; no password hash to extract".to_owned(),
        ));
    }
    let mut cursor = &document[offset_to_current_edit + 8..];
    let _last_slide = take_u32(&mut cursor)?;
    let _version = take_u16(&mut cursor)?;
    take(&mut cursor, 2)?;
    let _offset_last_edit = take_u32(&mut cursor)?;
    let offset_persist = take_u32(&mut cursor)? as usize;
    let _doc_persist = take_u32(&mut cursor)?;
    let _persist_seed = take_u32(&mut cursor)?;
    let _last_view = take_u16(&mut cursor)?;
    take(&mut cursor, 2)?;
    let encrypt_session = take_u16(&mut cursor)? as usize;
    let mut persist = document
        .get(offset_persist..)
        .ok_or_else(|| ExtractError::Invalid("PowerPoint persist offset".to_owned()))?;
    take(&mut persist, 8)?;
    take_u32(&mut persist)?;
    let mut persist_offset = 0u32;
    for _ in 0..encrypt_session {
        persist_offset = take_u32(&mut persist)?;
    }
    let start = persist_offset as usize;
    let mut cursor = document
        .get(start..)
        .ok_or_else(|| ExtractError::Invalid("PowerPoint persist record".to_owned()))?;
    take(&mut cursor, 8)?;
    let major = take_u16(&mut cursor)?;
    let minor = take_u16(&mut cursor)?;
    if major < 2 || minor != 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported PowerPoint encryption version {major}.{minor}"
        )));
    }
    let mut header = cursor;
    let _flags = take_u32(&mut header)?;
    let mut header_len = take_u32(&mut header)?;
    let _skip = take_u32(&mut header)?;
    header_len = header_len.saturating_sub(4);
    for _ in 0..3 {
        take_u32(&mut header)?;
        header_len = header_len.saturating_sub(4);
    }
    let key_size = take_u32(&mut header)?;
    header_len = header_len.saturating_sub(4);
    let _provider = take_u32(&mut header)?;
    header_len = header_len.saturating_sub(4);
    let _unused = take_u32(&mut header)?;
    header_len = header_len.saturating_sub(4);
    let _unused = take_u32(&mut header)?;
    header_len = header_len.saturating_sub(4);
    take(&mut header, header_len as usize)?;
    let version = match key_size {
        0 | 40 => 3,
        128 | 256 => 4,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported PowerPoint key size {other}"
            )));
        }
    };
    let mut verifier = read_verifier(&mut header, version)?;
    if verifier.version == 3 {
        verifier.second_block = document.get(..32).map_or_else(Vec::new, <[u8]>::to_vec);
    }
    Ok(verifier)
}

fn extract_verifier(cfb: &Cfb) -> Result<Verifier, ExtractError> {
    if cfb.has_stream("EncryptionInfo") {
        return Err(ExtractError::Unsupported(
            "this is an encrypted OOXML document".to_owned(),
        ));
    }
    if cfb.has_stream("Workbook") {
        return excel_verifier(cfb);
    }
    if cfb.has_stream("Book") {
        return excel_verifier_stream(cfb, "Book");
    }
    if cfb.has_stream("WordDocument") {
        return word_verifier(cfb);
    }
    if cfb.has_stream("PowerPoint Document") {
        return power_point_verifier(cfb);
    }
    Err(ExtractError::Unsupported(
        "no supported Office stream found".to_owned(),
    ))
}

fn hash_from_verifier(verifier: Verifier) -> Result<OldOffice, ExtractError> {
    let expected = match verifier.version {
        0 | 1 => 16,
        3 | 4 => 20,
        other => {
            return Err(ExtractError::Unsupported(format!(
                "unsupported Office version {other}"
            )));
        }
    };
    if verifier.hash.len() != expected {
        return Err(ExtractError::Invalid(
            "Office verifier hash has the wrong length".to_owned(),
        ));
    }
    Ok(OldOffice {
        version: verifier.version,
        salt: verifier.salt,
        verifier: verifier.verifier,
        key: verifier.hash,
        rc4_key: Vec::new(),
        second_block: verifier.second_block,
    })
}

fn hashes(data: Vec<u8>) -> Result<Vec<OldOffice>, ExtractError> {
    let cfb = Cfb::parse(data)?;
    let verifier = extract_verifier(&cfb)?;
    Ok(vec![hash_from_verifier(verifier)?])
}

impl Extractor for OldOfficeExtractor {
    fn slug(&self) -> &'static str {
        OldOffice::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        if data.len() < 512 || &data[..8] != CFB_SIGNATURE {
            return Probe::No;
        }
        match Cfb::parse(data) {
            Ok(cfb)
                if !cfb.has_stream("EncryptionInfo")
                    && (cfb.has_stream("Workbook")
                        || cfb.has_stream("WordDocument")
                        || cfb.has_stream("PowerPoint Document")) =>
            {
                Probe::yes("OLE compound file with an Office document stream")
            }
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = hashes(data)?;
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
