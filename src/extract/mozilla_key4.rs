//! Mozilla key4.db extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::MozillaKey4;
use crate::{HashType, HashValue};

pub struct MozillaKey4Extractor;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

const OID_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

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
        if length <= max_local {
            return self
                .data
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| ExtractError::Invalid("truncated SQLite payload".to_owned()));
        }
        let mut payload = self
            .data
            .get(start..start + max_local)
            .ok_or_else(|| ExtractError::Invalid("truncated SQLite payload".to_owned()))?
            .to_vec();
        let mut next = be_u32(self.data, start + max_local)
            .ok_or_else(|| ExtractError::Invalid("missing SQLite overflow page".to_owned()))?;
        let mut remaining = length - max_local;
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
        callback: &mut impl FnMut(&[u8]) -> Result<(), ExtractError>,
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
                varint(self.data, &mut offset)
                    .ok_or_else(|| ExtractError::Invalid("truncated SQLite rowid".to_owned()))?;
                let payload = self.read_payload(offset, length)?;
                callback(&payload)?;
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

fn metadata_row(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ExtractError> {
    let sqlite = Sqlite::new(data)?;
    let mut root = None;
    sqlite.walk_table(1, &mut |payload| {
        let values = parse_record(payload)?;
        if values.len() >= 4
            && values[0].text() == Some(b"table")
            && values[1]
                .text()
                .is_some_and(|name| name.eq_ignore_ascii_case(b"metadata"))
        {
            root = values[3].int().and_then(|page| u32::try_from(page).ok());
        }
        Ok(())
    })?;
    let root =
        root.ok_or_else(|| ExtractError::Unsupported("missing key4.db metadata table".to_owned()))?;

    let mut row = None;
    sqlite.walk_table(root, &mut |payload| {
        let values = parse_record(payload)?;
        if values.len() >= 3 && values[0].text() == Some(b"password") {
            if let (Some(salt), Some(item)) = (values[1].blob(), values[2].blob()) {
                row = Some((salt.to_vec(), item.to_vec()));
            }
        }
        Ok(())
    })?;
    row.ok_or_else(|| ExtractError::Unsupported("missing key4.db password metadata".to_owned()))
}

struct Der<'a> {
    tag: u8,
    value: &'a [u8],
    children: Vec<Der<'a>>,
}

fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), ExtractError> {
    let tag = *data
        .first()
        .ok_or_else(|| ExtractError::Invalid("truncated DER tag".to_owned()))?;
    let first = *data
        .get(1)
        .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(ExtractError::Invalid("invalid DER length".to_owned()));
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8)
                | usize::from(
                    *data
                        .get(2 + index)
                        .ok_or_else(|| ExtractError::Invalid("truncated DER length".to_owned()))?,
                );
        }
        (length, 2 + count)
    };
    let value = data
        .get(header..header + length)
        .ok_or_else(|| ExtractError::Invalid("truncated DER value".to_owned()))?;
    let rest = data
        .get(header + length..)
        .ok_or_else(|| ExtractError::Invalid("truncated DER value".to_owned()))?;
    Ok((tag, value, rest))
}

fn parse_der(data: &[u8]) -> Result<Der<'_>, ExtractError> {
    let (tag, value, _) = parse_tlv(data)?;
    let children = if tag & 0x20 != 0 {
        let mut children = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            let (_, _, next) = parse_tlv(rest)?;
            children.push(parse_der(rest)?);
            rest = next;
        }
        children
    } else {
        Vec::new()
    };
    Ok(Der {
        tag,
        value,
        children,
    })
}

fn child<'a>(der: &'a Der<'a>, index: usize) -> Result<&'a Der<'a>, ExtractError> {
    der.children
        .get(index)
        .ok_or_else(|| ExtractError::Invalid("missing DER field".to_owned()))
}

fn oid<'a>(der: &'a Der<'a>) -> Result<&'a [u8], ExtractError> {
    if der.tag != 0x06 {
        return Err(ExtractError::Invalid("expected DER OID".to_owned()));
    }
    Ok(der.value)
}

fn octets<'a>(der: &'a Der<'a>) -> Result<&'a [u8], ExtractError> {
    if der.tag != 0x04 {
        return Err(ExtractError::Invalid(
            "expected DER octet string".to_owned(),
        ));
    }
    Ok(der.value)
}

fn integer(der: &Der<'_>) -> Result<u64, ExtractError> {
    if der.tag != 0x02 || der.value.is_empty() || der.value.len() > 8 {
        return Err(ExtractError::Invalid("expected DER integer".to_owned()));
    }
    let mut value = 0u64;
    for byte in der.value {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn parse(artifact: &Artifact) -> Result<MozillaKey4, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let (global_salt, item) = metadata_row(&data)?;
    let root = parse_der(&item)?;
    if root.tag != 0x30 {
        return Err(ExtractError::Invalid("invalid key4.db ASN.1".to_owned()));
    }
    let algorithm = child(&root, 0)?;
    let ciphertext = octets(child(&root, 1)?)?;
    let algorithm_oid = oid(child(algorithm, 0)?)?;
    let parameters = child(algorithm, 1)?;
    if algorithm_oid == OID_3DES {
        return Err(ExtractError::Unsupported(
            "key4.db uses 3DES; use the key3 extractor".to_owned(),
        ));
    }
    if algorithm_oid != OID_PBES2 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db encryption algorithm".to_owned(),
        ));
    }
    let kdf = child(parameters, 0)?;
    if oid(child(kdf, 0)?)? != OID_PBKDF2 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db key derivation".to_owned(),
        ));
    }
    let pbkdf2 = child(kdf, 1)?;
    let entry_salt = octets(child(pbkdf2, 0)?)?;
    if entry_salt.len() != 32 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db entry salt length".to_owned(),
        ));
    }
    let iterations = integer(child(pbkdf2, 1)?)?;
    let key_length = integer(child(pbkdf2, 2)?)?;
    if key_length != 32 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db key length".to_owned(),
        ));
    }
    let prf = child(pbkdf2, 3)?;
    if oid(child(prf, 0)?)? != OID_HMAC_SHA256 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db PRF".to_owned(),
        ));
    }
    let encryption = child(parameters, 1)?;
    if oid(child(encryption, 0)?)? != OID_AES256_CBC {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db cipher".to_owned(),
        ));
    }
    let iv_value = octets(child(encryption, 1)?)?;
    if iv_value.len() != 14 {
        return Err(ExtractError::Invalid(
            "invalid key4.db initialization vector".to_owned(),
        ));
    }
    if ciphertext.len() != 16 {
        return Err(ExtractError::Invalid(
            "invalid key4.db ciphertext length".to_owned(),
        ));
    }
    if global_salt.len() != 20 && global_salt.len() != 48 {
        return Err(ExtractError::Unsupported(
            "unsupported key4.db global salt length".to_owned(),
        ));
    }
    let iterations = u32::try_from(iterations)
        .map_err(|_| ExtractError::Invalid("key4.db iteration count is too large".to_owned()))?;
    let mut iv = vec![0x04, 0x0e];
    iv.extend_from_slice(iv_value);
    Ok(MozillaKey4 {
        cipher: "AES".to_owned(),
        salt: crate::format::hex(global_salt),
        entry_salt: crate::format::hex(entry_salt),
        iterations,
        iv: crate::format::hex(iv),
        digest: ciphertext.to_vec(),
    })
}

impl Extractor for MozillaKey4Extractor {
    fn slug(&self) -> &'static str {
        MozillaKey4::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("key4.db SQLite metadata"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
