//! Jetico BestCrypt container extraction in the John serialization.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::BestcryptJohn;
use crate::{HashType, HashValue};

const HEADER_SIZE: usize = 4096;
const SIGNATURE_OFFSET: usize = 3;
const SIGNATURE_SIZE: usize = 8;
const LABEL_OFFSET: usize = 43;
const LABEL_SIZE: usize = 11;
const KEYGEN_OFFSET: usize = 54;
const VERSION_OFFSET: usize = 56;
const ITERATIONS_OFFSET: usize = 58;
const ALGORITHM_OFFSET: usize = 128;
const MODE_OFFSET: usize = 132;
const HASH_OFFSET: usize = 136;
const KEYMAP_OFFSET: usize = 140;
const KEYMAP_SIZE: usize = 512;
const KEYS_OFFSET: usize = 1536;
const SLOT_SIZE: usize = 8;
const KEY_SIZE: usize = 256;
const MAX_SLOTS: usize = 10;

const SIGNATURE: &[u8] = b"LOCOS94 ";
const VOLUME_LABEL: &[u8] = b"BC_KeyGenID";
const KEYGEN_V5: u16 = 5;
const KEYGEN_V4: u16 = 4;
const RIJNDAEL: u32 = 240;
const MODE_CBC: u32 = 0xBC00_0002;
const MODE_XTS: u32 = 0xBC00_0004;
const HASH_SHA256: u32 = 0x80;
const HASH_WHIRLPOOL512: u32 = 0x80 + 1;
const HASH_SHA512: u32 = 10;
const SLOT_PART: i16 = -1;
const SLOT_EMPTY: i16 = 0;
const SLOT_SALT: i16 = 5;

pub struct BestcryptJohnExtractor;

fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le_i16(data: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn salt_size(hash_id: u32) -> Option<usize> {
    match hash_id {
        HASH_SHA256 => Some(32),
        HASH_WHIRLPOOL512 | HASH_SHA512 => Some(64),
        _ => None,
    }
}

fn parse(artifact: &Artifact) -> Result<Vec<BestcryptJohn>, ExtractError> {
    let source = artifact.primary();
    if source.len() < HEADER_SIZE as u64 {
        return Err(ExtractError::Unsupported(
            "BestCrypt container header not found".to_owned(),
        ));
    }
    let mut data = [0u8; HEADER_SIZE];
    source
        .read_exact_at(0, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read BestCrypt header: {error}")))?;

    if &data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE] != SIGNATURE
        || &data[LABEL_OFFSET..LABEL_OFFSET + LABEL_SIZE] != VOLUME_LABEL
    {
        return Err(ExtractError::Unsupported(
            "BestCrypt header is encrypted or not a keygen container".to_owned(),
        ));
    }

    let keygen = le_u16(&data, KEYGEN_OFFSET);
    let version = le_u16(&data, VERSION_OFFSET);
    let iterations = le_u32(&data, ITERATIONS_OFFSET);
    let algorithm = le_u32(&data, ALGORITHM_OFFSET);
    let mode = le_u32(&data, MODE_OFFSET);
    let hash_id = le_u32(&data, HASH_OFFSET);

    if keygen != KEYGEN_V5 && (keygen != KEYGEN_V4 || iterations != 3) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported BestCrypt key generator {keygen} version {iterations}"
        )));
    }
    if algorithm != RIJNDAEL {
        return Err(ExtractError::Unsupported(format!(
            "unsupported BestCrypt cipher {algorithm}"
        )));
    }
    if mode != MODE_CBC && mode != MODE_XTS {
        return Err(ExtractError::Unsupported(format!(
            "unsupported BestCrypt cipher mode {mode:#x}"
        )));
    }
    let salt_size = salt_size(hash_id).ok_or_else(|| {
        ExtractError::Unsupported(format!("unsupported BestCrypt hash {hash_id}"))
    })?;

    let keymap = &data[KEYMAP_OFFSET..KEYMAP_OFFSET + KEYMAP_SIZE];
    if le_i16(keymap, 2) != SLOT_SALT {
        return Err(ExtractError::Invalid(
            "BestCrypt salt key slot is missing".to_owned(),
        ));
    }
    let keys = &data[KEYS_OFFSET..];
    let salt = crate::format::hex(&keys[..salt_size]);

    let mut values = Vec::new();
    for slot in 0..MAX_SLOTS {
        let slot_type = le_i16(keymap, SLOT_SIZE * slot + 2);
        if matches!(slot_type, SLOT_PART | SLOT_EMPTY | SLOT_SALT) {
            continue;
        }
        let key = &keys[KEY_SIZE * slot..KEY_SIZE * (slot + 1)];
        let fields = format!(
            "1${keygen}${version}${iterations}${algorithm}${mode}${hash_id}${salt_size}${salt}$1${}",
            crate::format::hex(key)
        );
        values.push(BestcryptJohn { data: fields });
    }

    Ok(values)
}

impl Extractor for BestcryptJohnExtractor {
    fn slug(&self) -> &'static str {
        BestcryptJohn::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("BestCrypt keygen container header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = parse(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no active BestCrypt key slots found".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
