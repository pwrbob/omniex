//! Apple iWork 2013/2014 password verifier extraction.

use std::io::{Cursor, Read};

use byteorder::{ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Iwork;
use crate::{HashType, HashValue};

pub struct IworkExtractor;

fn parse(artifact: &Artifact) -> Result<Iwork, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
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
    let data = verifier.ok_or_else(|| {
        ExtractError::Unsupported("no iWork 2013/2014 password verifier found".to_owned())
    })?;
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

impl Extractor for IworkExtractor {
    fn slug(&self) -> &'static str {
        Iwork::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("iWork password verifier"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
