//! Mozilla 3DES extraction from `key3.db` and `key4.db`.

use std::collections::HashMap;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Mozilla3des;
use crate::{HashType, HashValue};

pub struct Mozilla3desExtractor;

const MAGIC: u32 = 0x61561;
const VERSION: u32 = 2;

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn read_db(data: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, ExtractError> {
    if data.len() < 60 {
        return Err(ExtractError::Invalid("truncated key3.db header".to_owned()));
    }
    if be_u32(data, 0) != Some(MAGIC) {
        return Err(ExtractError::Unsupported("not a key3.db file".to_owned()));
    }
    if be_u32(data, 4) != Some(VERSION) {
        return Err(ExtractError::Unsupported(
            "unsupported key3.db version".to_owned(),
        ));
    }
    let pagesize = be_u32(data, 12)
        .filter(|size| *size >= 512 && *size <= 65536)
        .ok_or_else(|| ExtractError::Invalid("invalid key3.db page size".to_owned()))?
        as usize;
    let nkeys = be_u32(data, 56)
        .filter(|count| *count > 0 && *count <= 1_000_000)
        .ok_or_else(|| ExtractError::Invalid("invalid key3.db key count".to_owned()))?
        as usize;

    let mut readkeys = 0;
    let mut page: usize = 1;
    let mut chunks = Vec::new();
    while readkeys < nkeys {
        let page_start = page
            .checked_mul(pagesize)
            .filter(|start| *start < data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated key3.db page".to_owned()))?;
        let offsets_len = (nkeys + 1)
            .checked_mul(4)
            .and_then(|len| len.checked_add(2))
            .ok_or_else(|| ExtractError::Invalid("key3.db key count is too large".to_owned()))?;
        let offsets = data
            .get(page_start..page_start + offsets_len)
            .ok_or_else(|| ExtractError::Invalid("truncated key3.db offsets".to_owned()))?;

        let mut offset_vals = Vec::new();
        let mut i = 0;
        let mut nval = 0;
        let mut val = 1;
        let mut keys = 0;
        while nval != val {
            let key = le_u16(offsets, 2 + i)
                .ok_or_else(|| ExtractError::Invalid("truncated key3.db key".to_owned()))?;
            val = le_u16(offsets, 4 + i)
                .ok_or_else(|| ExtractError::Invalid("truncated key3.db value".to_owned()))?;
            nval = le_u16(offsets, 8 + i)
                .ok_or_else(|| ExtractError::Invalid("truncated key3.db next".to_owned()))?;
            offset_vals.push(page_start + key as usize);
            offset_vals.push(page_start + val as usize);
            readkeys += 1;
            keys += 1;
            i += 4;
            if keys > nkeys {
                return Err(ExtractError::Invalid(
                    "key3.db page has too many keys".to_owned(),
                ));
            }
        }
        offset_vals.push((page + 1) * pagesize);
        offset_vals.sort_unstable();
        for index in 0..keys * 2 {
            let start = offset_vals[index];
            let end = offset_vals[index + 1];
            if start > end || end > data.len() {
                return Err(ExtractError::Invalid(
                    "key3.db entry is out of bounds".to_owned(),
                ));
            }
            chunks.push(data[start..end].to_vec());
        }
        page += 1;
    }

    let mut db = HashMap::new();
    for pair in chunks.chunks_exact(2) {
        db.insert(pair[1].clone(), pair[0].clone());
    }
    Ok(db)
}

fn parse_key3(artifact: &Artifact) -> Result<Mozilla3des, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let db = read_db(&data)?;
    let global_salt = db
        .get(b"global-salt".as_slice())
        .ok_or_else(|| ExtractError::Unsupported("missing key3.db global-salt".to_owned()))?;
    let password_check = db
        .get(b"password-check".as_slice())
        .ok_or_else(|| ExtractError::Unsupported("missing key3.db password-check".to_owned()))?;
    if global_salt.len() != 20 {
        return Err(ExtractError::Unsupported(
            "unsupported key3.db global salt length".to_owned(),
        ));
    }
    let entry_salt_len = *password_check
        .get(1)
        .ok_or_else(|| ExtractError::Invalid("truncated key3.db password-check".to_owned()))?
        as usize;
    let entry_salt = password_check
        .get(3..3 + entry_salt_len)
        .ok_or_else(|| ExtractError::Invalid("truncated key3.db entry salt".to_owned()))?;
    if entry_salt.len() != 20 {
        return Err(ExtractError::Unsupported(
            "unsupported key3.db entry salt length".to_owned(),
        ));
    }
    let digest = password_check
        .get(password_check.len().saturating_sub(16)..)
        .filter(|digest| digest.len() == 16)
        .ok_or_else(|| ExtractError::Invalid("truncated key3.db verifier".to_owned()))?;
    Ok(Mozilla3des {
        cipher: "3DES".to_owned(),
        salt: crate::format::hex(global_salt),
        entry_salt: crate::format::hex(entry_salt),
        digest: digest.try_into().expect("16-byte digest"),
    })
}

fn parse(artifact: &Artifact) -> Result<Mozilla3des, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.starts_with(super::mozilla_aes::SQLITE_MAGIC) {
        return match super::mozilla_aes::parse_key4(&data)? {
            super::mozilla_aes::Key4::ThreeDes {
                global_salt,
                entry_salt,
                digest,
            } => Ok(Mozilla3des {
                cipher: "3DES".to_owned(),
                salt: crate::format::hex(&global_salt),
                entry_salt: crate::format::hex(&entry_salt),
                digest,
            }),
            super::mozilla_aes::Key4::Aes(_) => Err(ExtractError::Unsupported(
                "key4.db uses AES; use the mozilla-aes extractor".to_owned(),
            )),
        };
    }
    parse_key3(artifact)
}

impl Extractor for Mozilla3desExtractor {
    fn slug(&self) -> &'static str {
        Mozilla3des::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Mozilla 3DES database"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
