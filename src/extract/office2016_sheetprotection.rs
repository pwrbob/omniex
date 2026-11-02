//! MS Office 2016 worksheet protection extraction.

use std::io::{Cursor, Read};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Office2016Sheetprotection;
use crate::{HashType, HashValue};

pub struct Office2016SheetprotectionExtractor;

fn attribute<'a>(node: Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.name() == name)
        .map(|attribute| attribute.value())
}

fn decode(value: &str, name: &str) -> Result<Vec<u8>, ExtractError> {
    STANDARD
        .decode(value)
        .map_err(|error| ExtractError::Invalid(format!("invalid Office {name}: {error}")))
}

fn worksheet_hashes(xml: &str) -> Result<Vec<Office2016Sheetprotection>, ExtractError> {
    let document = roxmltree::Document::parse(xml)
        .map_err(|error| ExtractError::Invalid(format!("invalid worksheet XML: {error}")))?;
    let mut hashes = Vec::new();
    for node in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "sheetProtection")
    {
        let Some(hash_value) = attribute(node, "hashValue") else {
            continue;
        };
        let algorithm = attribute(node, "algorithmName").unwrap_or_default();
        if algorithm != "SHA-512" {
            continue;
        }
        let salt_value = attribute(node, "saltValue").ok_or_else(|| {
            ExtractError::Invalid("Office sheet protection has no salt".to_owned())
        })?;
        let spin_count = attribute(node, "spinCount")
            .ok_or_else(|| {
                ExtractError::Invalid("Office sheet protection has no spin count".to_owned())
            })?
            .parse::<u32>()
            .map_err(|_| {
                ExtractError::Invalid("invalid Office sheet protection spin count".to_owned())
            })?;
        let salt = decode(salt_value, "salt")?;
        let salt: [u8; 16] = salt.as_slice().try_into().map_err(|_| {
            ExtractError::Invalid("Office sheet protection salt must be 16 bytes".to_owned())
        })?;
        let digest = decode(hash_value, "hash")?;
        let digest: [u8; 64] = digest.as_slice().try_into().map_err(|_| {
            ExtractError::Invalid("Office sheet protection hash must be 64 bytes".to_owned())
        })?;
        hashes.push(Office2016Sheetprotection {
            spin_count,
            salt,
            digest,
        });
    }
    Ok(hashes)
}

fn hashes(data: Vec<u8>) -> Result<Vec<Office2016Sheetprotection>, ExtractError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|error| ExtractError::Invalid(format!("invalid Office ZIP: {error}")))?;
    let mut hashes = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ExtractError::Invalid(format!("invalid Office ZIP entry: {error}")))?;
        let name = entry.name().to_owned();
        if !name.starts_with("xl/worksheets/") || !name.ends_with(".xml") {
            continue;
        }
        let mut xml = String::new();
        entry
            .read_to_string(&mut xml)
            .map_err(|error| ExtractError::Invalid(format!("cannot read worksheet: {error}")))?;
        hashes.extend(worksheet_hashes(&xml)?);
    }
    Ok(hashes)
}

impl Extractor for Office2016SheetprotectionExtractor {
    fn slug(&self) -> &'static str {
        Office2016Sheetprotection::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match hashes(data) {
            Ok(hashes) if !hashes.is_empty() => Probe::yes("Office worksheet SHA-512 protection"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = hashes(data)?;
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no SHA-512 sheet protection records found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
