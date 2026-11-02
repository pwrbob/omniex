//! RAR3 header-encryption extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Rar3hp;
use crate::{HashType, HashValue};

pub struct Rar3hpExtractor;

const MARKER: &[u8] = b"Rar!\x1a\x07\x00";
const MAIN_HEAD: u8 = 0x73;
const HEADER_ENCRYPTED: u16 = 0x0080;
const TRAILER: usize = 24;

fn locate(data: &[u8]) -> Option<usize> {
    data.windows(MARKER.len())
        .position(|window| window == MARKER)
}

fn main_header_flags(data: &[u8], marker: usize) -> Option<u16> {
    let offset = marker + MARKER.len();
    let header = data.get(offset..offset + 7)?;
    if header[2] != MAIN_HEAD {
        return None;
    }
    Some(LittleEndian::read_u16(&header[3..5]))
}

fn parse(data: &[u8]) -> Result<Rar3hp, ExtractError> {
    let marker = locate(data)
        .ok_or_else(|| ExtractError::Unsupported("no RAR3 marker block found".to_owned()))?;
    let flags = main_header_flags(data, marker)
        .ok_or_else(|| ExtractError::Invalid("invalid RAR3 archive header".to_owned()))?;
    if flags & HEADER_ENCRYPTED == 0 {
        return Err(ExtractError::Unsupported(
            "RAR3 archive does not use header encryption".to_owned(),
        ));
    }
    if data.len() < TRAILER {
        return Err(ExtractError::Invalid(
            "RAR3 archive is too short for an encrypted header block".to_owned(),
        ));
    }
    let trailer = &data[data.len() - TRAILER..];
    let mut salt = [0; 8];
    salt.copy_from_slice(&trailer[..8]);
    let mut encrypted = [0; 16];
    encrypted.copy_from_slice(&trailer[8..]);
    Ok(Rar3hp {
        salt,
        data: encrypted,
    })
}

impl Extractor for Rar3hpExtractor {
    fn slug(&self) -> &'static str {
        Rar3hp::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match parse(&data) {
            Ok(_) => Probe::yes("RAR3 encrypted header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        Ok(vec![Box::new(parse(&data)?) as Box<dyn HashValue>])
    }
}
