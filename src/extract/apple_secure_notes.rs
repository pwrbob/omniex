//! Apple Secure Notes extraction from `NoteStore.sqlite` databases.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::AppleSecureNotes;
use crate::{HashType, HashValue};

pub struct AppleSecureNotesExtractor;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const NOTES_TABLE: &str = "ZICCLOUDSYNCINGOBJECT";
const SALT_LENGTH: usize = 16;
const DIGEST_LENGTH: usize = 24;

fn be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..9 {
        let byte = *data.get(*offset)?;
        *offset += 1;
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

struct Sqlite<'a> {
    data: &'a [u8],
    page_size: usize,
    usable: usize,
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Null,
    Int(i64),
    Text(&'a [u8]),
    Blob(&'a [u8]),
}

impl<'a> Value<'a> {
    fn text(self) -> Option<&'a [u8]> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    fn blob(self) -> Option<&'a [u8]> {
        match self {
            Self::Blob(value) => Some(value),
            _ => None,
        }
    }

    fn int(self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(value),
            _ => None,
        }
    }
}

impl<'a> Sqlite<'a> {
    fn new(data: &'a [u8]) -> Result<Self, ExtractError> {
        if data.get(..SQLITE_MAGIC.len()) != Some(SQLITE_MAGIC) {
            return Err(ExtractError::Unsupported(
                "not a SQLite database".to_owned(),
            ));
        }
        let page_size = match be_u16(data, 16) {
            Some(1) => 65536,
            Some(size) if size >= 512 && size.is_power_of_two() => usize::from(size),
            _ => {
                return Err(ExtractError::Invalid("invalid SQLite page size".to_owned()));
            }
        };
        let reserved = usize::from(*data.get(20).unwrap_or(&0));
        let usable = page_size
            .checked_sub(reserved)
            .filter(|usable| *usable >= 480)
            .ok_or_else(|| ExtractError::Invalid("invalid SQLite reserved size".to_owned()))?;
        Ok(Self {
            data,
            page_size,
            usable,
        })
    }

    fn page_start(&self, page: u32) -> Result<usize, ExtractError> {
        let page = usize::try_from(page)
            .map_err(|_| ExtractError::Invalid("SQLite page number is too large".to_owned()))?;
        page.checked_sub(1)
            .and_then(|page| page.checked_mul(self.page_size))
            .filter(|start| *start < self.data.len())
            .ok_or_else(|| ExtractError::Invalid("SQLite page is out of bounds".to_owned()))
    }

    fn read_payload(&self, start: usize, length: usize) -> Result<Vec<u8>, ExtractError> {
        let max_local = self.usable.saturating_sub(35);
        let local = if length <= max_local {
            length
        } else {
            let min_local = (self.usable.saturating_sub(12) * 32 / 255).saturating_sub(23);
            let local = min_local + (length - min_local) % self.usable.saturating_sub(4);
            if local <= max_local { local } else { min_local }
        };
        let mut payload = self
            .data
            .get(start..start + local)
            .ok_or_else(|| ExtractError::Invalid("truncated SQLite payload".to_owned()))?
            .to_vec();
        if length <= max_local {
            return Ok(payload);
        }
        let mut next = be_u32(self.data, start + local)
            .ok_or_else(|| ExtractError::Invalid("missing SQLite overflow page".to_owned()))?;
        let mut remaining = length - local;
        while remaining > 0 {
            let page_start = self.page_start(next)?;
            next = be_u32(self.data, page_start).ok_or_else(|| {
                ExtractError::Invalid("truncated SQLite overflow page".to_owned())
            })?;
            let chunk = remaining.min(self.usable.saturating_sub(4));
            let bytes = self
                .data
                .get(page_start + 4..page_start + 4 + chunk)
                .ok_or_else(|| {
                    ExtractError::Invalid("truncated SQLite overflow data".to_owned())
                })?;
            payload.extend_from_slice(bytes);
            remaining -= chunk;
        }
        Ok(payload)
    }

    fn walk_table(
        &self,
        page: u32,
        callback: &mut impl FnMut(&[u8], i64) -> Result<(), ExtractError>,
    ) -> Result<(), ExtractError> {
        let page_start = self.page_start(page)?;
        let header = if page == 1 { 100 } else { 0 };
        let kind = *self
            .data
            .get(page_start + header)
            .ok_or_else(|| ExtractError::Invalid("truncated SQLite page header".to_owned()))?;
        let cells = usize::from(
            be_u16(self.data, page_start + header + 3)
                .ok_or_else(|| ExtractError::Invalid("truncated SQLite cell count".to_owned()))?,
        );
        let header_size = match kind {
            0x0d => 8,
            0x05 => 12,
            _ => {
                return Err(ExtractError::Invalid(
                    "unsupported SQLite b-tree page".to_owned(),
                ));
            }
        };
        let pointers = page_start + header + header_size;
        for index in 0..cells {
            let pointer = usize::from(
                be_u16(self.data, pointers + index * 2)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite cell".to_owned()))?,
            );
            let cell = page_start + pointer;
            if kind == 0x05 {
                let child = be_u32(self.data, cell)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite child".to_owned()))?;
                self.walk_table(child, callback)?;
            } else {
                let mut offset = cell;
                let length = varint(self.data, &mut offset).ok_or_else(|| {
                    ExtractError::Invalid("truncated SQLite payload length".to_owned())
                })? as usize;
                let rowid = varint(self.data, &mut offset)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite rowid".to_owned()))?
                    as i64;
                let payload = self.read_payload(offset, length)?;
                callback(&payload, rowid)?;
            }
        }
        if kind == 0x05 {
            let right = be_u32(self.data, page_start + header + 8)
                .ok_or_else(|| ExtractError::Invalid("truncated SQLite right child".to_owned()))?;
            self.walk_table(right, callback)?;
        }
        Ok(())
    }
}

fn parse_record(payload: &[u8]) -> Result<Vec<Value<'_>>, ExtractError> {
    let mut offset = 0;
    let header_len = varint(payload, &mut offset)
        .ok_or_else(|| ExtractError::Invalid("truncated SQLite record header".to_owned()))?
        as usize;
    if header_len > payload.len() || header_len < offset {
        return Err(ExtractError::Invalid(
            "invalid SQLite record header".to_owned(),
        ));
    }
    let mut serials = Vec::new();
    while offset < header_len {
        serials.push(
            varint(payload, &mut offset)
                .ok_or_else(|| ExtractError::Invalid("truncated SQLite serial type".to_owned()))?,
        );
    }
    let mut body = header_len;
    let mut values = Vec::with_capacity(serials.len());
    for serial in serials {
        let (size, value) = match serial {
            0 => (0, Value::Null),
            1..=6 => {
                let size = match serial {
                    1 => 1,
                    2 => 2,
                    3 => 3,
                    4 => 4,
                    5 => 6,
                    _ => 8,
                };
                let bytes = payload
                    .get(body..body + size)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite integer".to_owned()))?;
                let mut value = 0i64;
                for byte in bytes {
                    value = (value << 8) | i64::from(*byte);
                }
                let shift = 64 - size * 8;
                (size, Value::Int((value << shift) >> shift))
            }
            7 => {
                let bytes = payload
                    .get(body..body + 8)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite float".to_owned()))?;
                (8, Value::Int(i64::from_be_bytes(bytes.try_into().unwrap())))
            }
            8 => (0, Value::Int(0)),
            9 => (0, Value::Int(1)),
            10 | 11 => (0, Value::Null),
            _ => {
                let size = if serial % 2 == 0 {
                    (serial - 12) / 2
                } else {
                    (serial - 13) / 2
                } as usize;
                let bytes = payload
                    .get(body..body + size)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite value".to_owned()))?;
                let value = if serial % 2 == 0 {
                    Value::Blob(bytes)
                } else {
                    Value::Text(bytes)
                };
                (size, value)
            }
        };
        body += size;
        values.push(value);
    }
    Ok(values)
}

fn push_column(segment: &str, columns: &mut Vec<String>) {
    let Some(token) = segment.split_whitespace().next() else {
        return;
    };
    let token = token.trim_matches(|character| {
        matches!(character, '"' | '\'' | '`' | '[' | ']') || character.is_whitespace()
    });
    if token.is_empty() {
        return;
    }
    let keyword = token.to_ascii_uppercase();
    if matches!(
        keyword.as_str(),
        "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN"
    ) {
        return;
    }
    columns.push(token.to_owned());
}

fn column_names(sql: &[u8]) -> Result<Vec<String>, ExtractError> {
    let text = str::from_utf8(sql)
        .map_err(|_| ExtractError::Invalid("notes schema is not UTF-8".to_owned()))?;
    let start = text
        .find('(')
        .ok_or_else(|| ExtractError::Invalid("notes schema has no column list".to_owned()))?;
    let end = text
        .rfind(')')
        .ok_or_else(|| ExtractError::Invalid("notes schema has no column list".to_owned()))?;
    if end <= start {
        return Err(ExtractError::Invalid(
            "notes schema has an invalid column list".to_owned(),
        ));
    }
    let body = &text[start + 1..end];
    let mut columns = Vec::new();
    let mut segment = String::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    for character in body.chars() {
        if let Some(closing) = quote {
            segment.push(character);
            if character == closing {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                quote = Some(character);
                segment.push(character);
            }
            '[' => {
                quote = Some(']');
                segment.push(character);
            }
            '(' => {
                depth += 1;
                segment.push(character);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                segment.push(character);
            }
            ',' if depth == 0 => {
                push_column(&segment, &mut columns);
                segment.clear();
            }
            _ => segment.push(character),
        }
    }
    push_column(&segment, &mut columns);
    Ok(columns)
}

fn table_root(db: &Sqlite<'_>, name: &str) -> Result<Option<(u32, Vec<String>)>, ExtractError> {
    let mut found = None;
    db.walk_table(1, &mut |payload, _| {
        let values = parse_record(payload)?;
        if values.len() < 5
            || values[0].text() != Some(b"table")
            || values[1].text() != Some(name.as_bytes())
        {
            return Ok(());
        }
        let Some(root) = values[3].int().and_then(|page| u32::try_from(page).ok()) else {
            return Ok(());
        };
        let Some(sql) = values[4].text() else {
            return Ok(());
        };
        found = Some((root, column_names(sql)?));
        Ok(())
    })?;
    Ok(found)
}

fn parse(artifact: &Artifact) -> Result<Vec<AppleSecureNotes>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.is_empty() {
        return Err(ExtractError::Invalid(
            "Apple Notes database is empty".to_owned(),
        ));
    }
    let db = Sqlite::new(&data)?;
    let (root, columns) = table_root(&db, NOTES_TABLE)?
        .ok_or_else(|| ExtractError::Unsupported("no Apple Notes crypto table".to_owned()))?;
    let index = |name: &str| {
        columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(name))
    };
    let pk = index("Z_PK")
        .ok_or_else(|| ExtractError::Unsupported("notes table has no Z_PK".to_owned()))?;
    let iterations = index("ZCRYPTOITERATIONCOUNT").ok_or_else(|| {
        ExtractError::Unsupported("notes table has no ZCRYPTOITERATIONCOUNT".to_owned())
    })?;
    let salt = index("ZCRYPTOSALT")
        .ok_or_else(|| ExtractError::Unsupported("notes table has no ZCRYPTOSALT".to_owned()))?;
    let wrapped = index("ZCRYPTOWRAPPEDKEY").ok_or_else(|| {
        ExtractError::Unsupported("notes table has no ZCRYPTOWRAPPEDKEY".to_owned())
    })?;
    let verifier = index("ZCRYPTOVERIFIER").ok_or_else(|| {
        ExtractError::Unsupported("notes table has no ZCRYPTOVERIFIER".to_owned())
    })?;

    let mut hashes = Vec::new();
    db.walk_table(root, &mut |payload, rowid| {
        let values = parse_record(payload)?;
        let Some(iterations) = values
            .get(iterations)
            .and_then(|value| value.int())
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
        else {
            return Ok(());
        };
        let Some(salt) = values.get(salt).and_then(|value| value.blob()) else {
            return Ok(());
        };
        let digest = values
            .get(wrapped)
            .and_then(|value| value.blob())
            .or_else(|| values.get(verifier).and_then(|value| value.blob()));
        let Some(digest) = digest else {
            return Ok(());
        };
        let version = values
            .get(pk)
            .and_then(|value| value.int())
            .unwrap_or(rowid);
        let version = u32::try_from(version)
            .map_err(|_| ExtractError::Invalid("invalid Apple Notes Z_PK".to_owned()))?;
        if salt.len() != SALT_LENGTH {
            return Err(ExtractError::Invalid(
                "Apple Notes salt must be 16 bytes".to_owned(),
            ));
        }
        if digest.len() != DIGEST_LENGTH {
            return Err(ExtractError::Invalid(
                "Apple Notes digest must be 24 bytes".to_owned(),
            ));
        }
        hashes.push(AppleSecureNotes {
            version,
            iterations,
            salt: crate::format::hex(salt),
            digest: digest.try_into().expect("twenty-four-byte digest"),
        });
        Ok(())
    })?;
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no protected Apple Notes records".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for AppleSecureNotesExtractor {
    fn slug(&self) -> &'static str {
        AppleSecureNotes::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Apple Notes crypto records"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
