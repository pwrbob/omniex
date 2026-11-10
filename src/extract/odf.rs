//! OpenDocument encrypted package extraction.

use std::io::{Cursor, Read};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Odf;
use crate::{HashType, HashValue};

pub struct OdfExtractor;

fn attribute<'a>(node: Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.name() == name)
        .map(|attribute| attribute.value())
}

fn required<'a>(node: Node<'a, 'a>, name: &str) -> Result<&'a str, ExtractError> {
    attribute(node, name)
        .ok_or_else(|| ExtractError::Invalid(format!("missing ODF manifest attribute `{name}`")))
}

fn child<'a>(node: Node<'a, 'a>, tag: &str) -> Option<Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == tag)
}

fn nested_required<'a>(node: Node<'a, 'a>, tag: &str, name: &str) -> Result<&'a str, ExtractError> {
    child(node, tag)
        .and_then(|child| attribute(child, name))
        .or_else(|| attribute(node, name))
        .ok_or_else(|| ExtractError::Invalid(format!("missing ODF manifest attribute `{name}`")))
}

fn parse(artifact: &Artifact) -> Result<Odf, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|error| ExtractError::Invalid(format!("invalid ODF ZIP: {error}")))?;
    let manifest = {
        let mut entry = archive
            .by_name("META-INF/manifest.xml")
            .map_err(|_| ExtractError::Unsupported("missing ODF manifest".to_owned()))?;
        let mut xml = String::new();
        entry
            .read_to_string(&mut xml)
            .map_err(|error| ExtractError::Invalid(format!("cannot read ODF manifest: {error}")))?;
        xml
    };
    let document = roxmltree::Document::parse(&manifest)
        .map_err(|error| ExtractError::Invalid(format!("invalid ODF manifest XML: {error}")))?;
    if document
        .descendants()
        .any(|node| node.is_element() && attribute(node, "full-path") == Some("encrypted-package"))
    {
        return Err(ExtractError::Unsupported(
            "unsupported encrypted ODF package".to_owned(),
        ));
    }
    let encryption = document
        .descendants()
        .find(|node| node.is_element() && attribute(*node, "checksum").is_some())
        .ok_or_else(|| ExtractError::Unsupported("ODF package is not encrypted".to_owned()))?;

    let algorithm = nested_required(encryption, "algorithm", "algorithm-name")?;
    let cipher_type = if algorithm.contains("aes256-cbc") {
        1
    } else if algorithm.contains("Blowfish CFB") {
        0
    } else {
        return Err(ExtractError::Unsupported(format!(
            "unsupported ODF algorithm `{algorithm}`"
        )));
    };
    let checksum_type_name = required(encryption, "checksum-type")?;
    let checksum_type = if checksum_type_name.to_ascii_uppercase().contains("SHA256") {
        1
    } else if checksum_type_name.to_ascii_uppercase().contains("SHA1") {
        0
    } else {
        return Err(ExtractError::Unsupported(format!(
            "unsupported ODF checksum `{checksum_type_name}`"
        )));
    };
    let start_key = nested_required(
        encryption,
        "start-key-generation",
        "start-key-generation-name",
    )?;
    let start_key_type = if start_key.to_ascii_uppercase().contains("SHA256") {
        1
    } else if start_key.to_ascii_uppercase().contains("SHA1") {
        0
    } else {
        return Err(ExtractError::Unsupported(format!(
            "unsupported ODF start-key generation `{start_key}`"
        )));
    };
    if start_key_type != checksum_type {
        return Err(ExtractError::Unsupported(
            "unsupported combination of ODF checksum and start-key algorithms".to_owned(),
        ));
    }
    let number = |name: &str| -> Result<u32, ExtractError> {
        nested_required(encryption, "key-derivation", name)?
            .parse::<u32>()
            .map_err(|_| ExtractError::Invalid(format!("invalid ODF `{name}`")))
    };
    let iterations = number("iteration-count")?;
    let key_size = number("key-size")?;
    let decode = |name: &str| -> Result<Vec<u8>, ExtractError> {
        STANDARD
            .decode(nested_required(encryption, "key-derivation", name)?)
            .map_err(|_| ExtractError::Invalid(format!("invalid ODF `{name}`")))
    };
    let checksum = decode("checksum")?;
    let iv = STANDARD
        .decode(nested_required(
            encryption,
            "algorithm",
            "initialisation-vector",
        )?)
        .map_err(|_| ExtractError::Invalid("invalid ODF `initialisation-vector`".to_owned()))?;
    let salt = decode("salt")?;

    let content = {
        let entry = archive
            .by_name("content.xml")
            .map_err(|_| ExtractError::Unsupported("missing ODF content.xml".to_owned()))?;
        let mut data = Vec::new();
        entry
            .take(1024)
            .read_to_end(&mut data)
            .map_err(|error| ExtractError::Invalid(format!("cannot read ODF content: {error}")))?;
        data
    };

    Ok(Odf {
        cipher_type,
        checksum_type,
        iterations,
        key_size,
        checksum: crate::format::hex(&checksum),
        iv_size: u8::try_from(iv.len())
            .map_err(|_| ExtractError::Invalid("ODF IV is too large".to_owned()))?,
        iv: crate::format::hex(&iv),
        salt_size: u8::try_from(salt.len())
            .map_err(|_| ExtractError::Invalid("ODF salt is too large".to_owned()))?,
        salt: crate::format::hex(&salt),
        unused: 0,
        data: crate::format::hex(&content),
    })
}

impl Extractor for OdfExtractor {
    fn slug(&self) -> &'static str {
        Odf::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("encrypted OpenDocument manifest"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
