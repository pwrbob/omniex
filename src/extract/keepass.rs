//! KeePass KDBX v2 and v3 database extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Keepass;
use crate::{HashType, HashValue};

const SIGNATURE_PRIMARY: u32 = 0x9AA2_D903;
const SIGNATURE_SECONDARY: u32 = 0xB54B_FB67;
const SIGNATURE_SECONDARY_PRE: u32 = 0xB54B_FB66;
const SIGNATURE_LEGACY: u32 = 0xB54B_FB65;
const VERSION_4: u32 = 0x0004_0000;

const FIELD_CIPHER: u8 = 2;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_TRANSFORM_SEED: u8 = 5;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_IV: u8 = 7;
const FIELD_STREAM_START: u8 = 9;

pub struct KeepassExtractor;

struct Cursor<'a> {
    source: &'a dyn super::ReadAt,
    offset: u64,
    len: u64,
}

impl<'a> Cursor<'a> {
    fn new(source: &'a dyn super::ReadAt) -> Self {
        Self {
            source,
            offset: 0,
            len: source.len(),
        }
    }

    fn bytes(&mut self, count: usize) -> Result<Vec<u8>, ExtractError> {
        let mut data = vec![0; count];
        self.source
            .read_exact_at(self.offset, &mut data)
            .map_err(|error| ExtractError::Invalid(format!("truncated KeePass header: {error}")))?;
        self.offset += count as u64;
        Ok(data)
    }

    fn u8(&mut self) -> Result<u8, ExtractError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ExtractError> {
        let data = self.bytes(2)?;
        Ok(u16::from_le_bytes([data[0], data[1]]))
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        let data = self.bytes(4)?;
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.offset)
    }
}

fn algorithm(cipher: &[u8]) -> Result<u8, ExtractError> {
    match cipher.get(..4) {
        Some([0x31, 0xc1, 0xf2, 0xe6]) => Ok(0),
        Some([0xad, 0x68, 0xf2, 0x9f]) => Ok(1),
        Some([0xd6, 0x03, 0x8a, 0x2b]) => Ok(2),
        _ => Err(ExtractError::Unsupported(
            "unsupported KeePass cipher".to_owned(),
        )),
    }
}

fn rounds(data: &[u8]) -> u64 {
    let mut value = 0;
    for (shift, byte) in data.iter().take(8).enumerate() {
        value |= u64::from(*byte) << (8 * shift);
    }
    value
}

fn required(field: Option<Vec<u8>>, name: &str) -> Result<Vec<u8>, ExtractError> {
    field.ok_or_else(|| ExtractError::Invalid(format!("missing KeePass {name}")))
}

fn parse(artifact: &Artifact) -> Result<Keepass, ExtractError> {
    let mut cursor = Cursor::new(artifact.primary());
    if cursor.remaining() < 12 {
        return Err(ExtractError::Invalid(
            "KeePass database is truncated".to_owned(),
        ));
    }
    if cursor.u32()? != SIGNATURE_PRIMARY {
        return Err(ExtractError::Unsupported(
            "missing KeePass signature".to_owned(),
        ));
    }
    let signature = cursor.u32()?;
    if signature == SIGNATURE_LEGACY {
        return Err(ExtractError::Unsupported("KeePass 1.x database".to_owned()));
    }
    if signature != SIGNATURE_SECONDARY && signature != SIGNATURE_SECONDARY_PRE {
        return Err(ExtractError::Unsupported(
            "missing KeePass signature".to_owned(),
        ));
    }
    let version = cursor.u32()?;
    if version & 0xffff_0000 >= VERSION_4 {
        return Err(ExtractError::Unsupported(
            "KeePass KDBX v4 database".to_owned(),
        ));
    }

    let mut cipher = None;
    let mut master_seed = None;
    let mut transform_seed = None;
    let mut transform_rounds = None;
    let mut iv = None;
    let mut stream_start = None;

    loop {
        let id = cursor.u8()?;
        let size = usize::from(cursor.u16()?);
        if id == 0 {
            if size != 0 {
                return Err(ExtractError::Invalid(
                    "invalid KeePass end-of-header field".to_owned(),
                ));
            }
            break;
        }
        if size == 0 {
            return Err(ExtractError::Invalid(
                "zero-length KeePass header field".to_owned(),
            ));
        }
        let data = cursor.bytes(size)?;
        match id {
            FIELD_CIPHER => cipher = Some(data),
            FIELD_MASTER_SEED => master_seed = Some(data),
            FIELD_TRANSFORM_SEED => transform_seed = Some(data),
            FIELD_TRANSFORM_ROUNDS => transform_rounds = Some(data),
            FIELD_IV => iv = Some(data),
            FIELD_STREAM_START => stream_start = Some(data),
            _ => {}
        }
    }

    let algorithm = algorithm(&required(cipher, "cipher")?)?;
    let master_seed = required(master_seed, "master seed")?;
    let transform_seed = required(transform_seed, "transform seed")?;
    let transform_rounds = required(transform_rounds, "transform rounds")?;
    let iv = required(iv, "initialization vector")?;
    let stream_start = required(stream_start, "stream start bytes")?;
    if transform_rounds.is_empty() {
        return Err(ExtractError::Invalid(
            "KeePass transform rounds are empty".to_owned(),
        ));
    }
    let round_count = rounds(&transform_rounds);
    if round_count == 0 {
        return Err(ExtractError::Invalid(
            "KeePass transform rounds cannot be zero".to_owned(),
        ));
    }

    let encrypted = cursor.bytes(32)?;

    Ok(Keepass {
        version: 2,
        rounds: round_count,
        algorithm,
        seed: crate::format::hex(&master_seed),
        transform_seed: crate::format::hex(&transform_seed),
        iv: crate::format::hex(&iv),
        details: format!(
            "{}*{}",
            crate::format::hex(&stream_start),
            crate::format::hex(&encrypted)
        ),
    })
}

impl Extractor for KeepassExtractor {
    fn slug(&self) -> &'static str {
        Keepass::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let mut signature = [0; 8];
        match artifact.primary().read_at(0, &mut signature) {
            Ok(8) => {}
            Ok(_) => return Probe::No,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        }
        let primary = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        let secondary =
            u32::from_le_bytes([signature[4], signature[5], signature[6], signature[7]]);
        if primary != SIGNATURE_PRIMARY
            || (secondary != SIGNATURE_SECONDARY && secondary != SIGNATURE_SECONDARY_PRE)
        {
            return Probe::No;
        }
        match parse(artifact) {
            Ok(_) => Probe::yes("KeePass KDBX v2/v3 header"),
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
