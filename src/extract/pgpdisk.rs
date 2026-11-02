//! PGP Virtual Disk user-record extraction.

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Pgpdisk;
use crate::{HashType, HashValue};

pub struct PgpdiskExtractor;

const MAIN_SIZE: usize = 356;
const USER_SIZE: usize = 312;

fn parse(artifact: &Artifact) -> Result<Extracted, ExtractError> {
    let source = artifact.primary();
    let mut data = vec![0; 4096];
    let header_len = usize::try_from(source.len().min(4096)).expect("header length");
    source
        .read_exact_at(0, &mut data[..header_len])
        .map_err(|error| ExtractError::Invalid(format!("cannot read DMG: {error}")))?;
    let mut header = None;
    for offset in 0..data.len().saturating_sub(MAIN_SIZE) {
        if &data[offset..offset + 4] == b"PGPd" && &data[offset + 4..offset + 8] == b"MAIN" {
            header = Some(offset);
            break;
        }
    }
    let offset = header.ok_or_else(|| {
        ExtractError::Unsupported("PGP Virtual Disk main header not found".to_owned())
    })?;
    let algorithm = LittleEndian::read_u32(&data[offset + 60..offset + 64]);
    if !matches!(algorithm, 3..=7) {
        return Err(ExtractError::Unsupported(
            "unsupported PGP Virtual Disk algorithm".to_owned(),
        ));
    }
    let next = LittleEndian::read_u64(&data[offset + 16..offset + 24]);
    let salt = &data[offset + 64..offset + 80];
    let salt = salt.to_vec();

    let mut users = vec![0; 1 << 20];
    let user_len = usize::try_from(source.len().saturating_sub(next).min(1 << 20))
        .map_err(|_| ExtractError::Invalid("PGP Virtual Disk is too large".to_owned()))?;
    source
        .read_exact_at(next, &mut users[..user_len])
        .map_err(|error| ExtractError::Invalid(format!("cannot read PGP user area: {error}")))?;
    let mut hashes = Vec::new();
    for offset in 0..users.len().saturating_sub(USER_SIZE) {
        let record = &users[offset..offset + USER_SIZE];
        if &record[..4] != b"USER" || &record[4..8] != b"SYMM" {
            continue;
        }
        let iterations = LittleEndian::read_u16(&record[304..306]);
        let check = &record[288..304];
        hashes.push(Pgpdisk {
            version: 0,
            count: algorithm as u8,
            iterations: u32::from(iterations),
            salt: salt.clone().try_into().expect("16-byte salt"),
            digest: check.try_into().expect("16-byte check bytes"),
        });
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no PGP Virtual Disk users found".to_owned(),
        ));
    }
    Ok(hashes
        .into_iter()
        .map(|hash| Box::new(hash) as Box<dyn HashValue>)
        .collect())
}

impl Extractor for PgpdiskExtractor {
    fn slug(&self) -> &'static str {
        Pgpdisk::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("PGP Virtual Disk main header"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        parse(artifact)
    }
}
