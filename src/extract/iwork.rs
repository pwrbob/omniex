//! Apple iWork 2009 and 2013/2014 password verifier extraction.

use std::io::{Cursor, Read};

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Iwork;
use crate::{HashType, HashValue};

pub struct IworkExtractor;

enum Format {
    Modern,
    Legacy,
}

fn parse(artifact: &Artifact) -> Result<(Iwork, Format), ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut archive = zip::ZipArchive::new(Cursor::new(data.as_slice()))
        .map_err(|error| ExtractError::Invalid(format!("invalid iWork ZIP: {error}")))?;
    let mut verifier = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ExtractError::Invalid(format!("invalid iWork entry: {error}")))?;
        if entry.name().ends_with(".iwpv2") {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).map_err(|error| {
                ExtractError::Invalid(format!("cannot read iWork verifier: {error}"))
            })?;
            verifier = Some(data);
            break;
        }
    }
    if let Some(data) = verifier {
        return Ok((parse_modern(&data)?, Format::Modern));
    }
    Ok((parse_legacy(&data)?, Format::Legacy))
}

fn parse_modern(data: &[u8]) -> Result<Iwork, ExtractError> {
    if data.len() != 104 {
        return Err(ExtractError::Invalid(
            "iWork password verifier has the wrong length".to_owned(),
        ));
    }
    let version = LittleEndian::read_u16(&data[0..2]);
    let format = LittleEndian::read_u16(&data[2..4]);
    if version != 2 || format != 1 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported iWork verifier version {version} format {format}"
        )));
    }
    let iterations = LittleEndian::read_u32(&data[4..8]);
    let salt = data[8..24].to_vec();
    let iv: [u8; 16] = data[24..40].try_into().expect("16-byte IV");
    let blob = data[40..104].to_vec();

    Ok(Iwork {
        hash_version: 1,
        file_version: 2,
        format_version: 1,
        iterations,
        salt,
        iv,
        data: blob,
    })
}

fn parse_legacy(data: &[u8]) -> Result<Iwork, ExtractError> {
    if !data.starts_with(b"PK\x03\x04") {
        return Err(ExtractError::Unsupported(
            "not an iWork 2009 ZIP archive".to_owned(),
        ));
    }
    let eocd = data
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or_else(|| ExtractError::Unsupported("no iWork 2009 ZIP end record".to_owned()))?;
    if eocd + 20 > data.len() {
        return Err(ExtractError::Invalid(
            "truncated iWork ZIP end record".to_owned(),
        ));
    }
    let central = LittleEndian::read_u32(&data[eocd + 16..eocd + 20]) as usize;
    if central + 46 > data.len() {
        return Err(ExtractError::Invalid(
            "truncated iWork central directory".to_owned(),
        ));
    }

    let mut position = central;
    while position + 46 <= data.len() {
        if &data[position..position + 4] != b"PK\x01\x02" {
            break;
        }
        let name_length = LittleEndian::read_u16(&data[position + 28..position + 30]) as usize;
        let extra_length = LittleEndian::read_u16(&data[position + 30..position + 32]) as usize;
        let comment_length = LittleEndian::read_u16(&data[position + 32..position + 34]) as usize;
        let extra = position + 46 + name_length;
        let extra_end = extra + extra_length;
        if extra_end > data.len() {
            return Err(ExtractError::Invalid(
                "truncated iWork central directory entry".to_owned(),
            ));
        }
        if extra_length >= 96 {
            let version = LittleEndian::read_u16(&data[extra + 8..extra + 10]);
            let format = LittleEndian::read_u16(&data[extra + 10..extra + 12]);
            if version == 1 && format == 1 {
                let iterations = LittleEndian::read_u32(&data[extra + 12..extra + 16]);
                let verifier = &data[extra + 16..extra + 96];
                let iv: [u8; 16] = verifier[..16].try_into().expect("16-byte IV");
                return Ok(Iwork {
                    hash_version: 2,
                    file_version: 1,
                    format_version: 1,
                    iterations,
                    salt: b"someSalt".to_vec(),
                    iv,
                    data: verifier[16..].to_vec(),
                });
            }
        }
        position = extra_end + comment_length;
    }

    Err(ExtractError::Unsupported(
        "no iWork 2009 password verifier found".to_owned(),
    ))
}

impl Extractor for IworkExtractor {
    fn slug(&self) -> &'static str {
        Iwork::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok((_, Format::Modern)) => Probe::yes("iWork password verifier"),
            Ok((_, Format::Legacy)) => Probe::yes("iWork 2009 password verifier"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?.0) as Box<dyn HashValue>])
    }
}
