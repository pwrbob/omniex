//! Signal Android secure preference extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Signal;
use crate::{HashType, HashValue};

pub struct SignalExtractor;

fn child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.has_tag_name(tag))
}

fn string_field<'a, 'input>(map: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    map.children()
        .filter(|node| node.is_element() && node.has_tag_name("string"))
        .find(|node| node.attribute("name") == Some(name))
        .and_then(|node| node.text())
        .map(str::trim)
}

fn decode(value: &str, field: &str) -> Result<Vec<u8>, ExtractError> {
    STANDARD
        .decode(value)
        .map_err(|_| ExtractError::Invalid(format!("invalid Signal {field} base64")))
}

fn record(map: Node) -> Result<Option<Signal>, ExtractError> {
    let Some(enabled) = child(map, "boolean").and_then(|node| node.attribute("value")) else {
        return Ok(None);
    };
    if enabled.trim() != "true" {
        return Ok(None);
    }
    let iterations = child(map, "int")
        .and_then(|node| node.attribute("value"))
        .ok_or_else(|| ExtractError::Invalid("missing Signal password iteration count".to_owned()))?
        .trim()
        .parse::<u32>()
        .map_err(|_| ExtractError::Invalid("invalid Signal password iteration count".to_owned()))?;

    let encryption_salt = string_field(map, "encryption_salt")
        .ok_or_else(|| ExtractError::Invalid("missing Signal encryption salt".to_owned()))?;
    let mac_salt = string_field(map, "mac_salt")
        .ok_or_else(|| ExtractError::Invalid("missing Signal MAC salt".to_owned()))?;
    let master_secret = string_field(map, "master_secret")
        .ok_or_else(|| ExtractError::Invalid("missing Signal master secret".to_owned()))?;

    let salt: [u8; 16] = decode(encryption_salt, "encryption salt")?
        .try_into()
        .map_err(|_| ExtractError::Invalid("Signal encryption salt is not 16 bytes".to_owned()))?;
    let digest: [u8; 16] = decode(mac_salt, "MAC salt")?
        .try_into()
        .map_err(|_| ExtractError::Invalid("Signal MAC salt is not 16 bytes".to_owned()))?;
    let secret = decode(master_secret, "master secret")?;
    if secret.len() < 20 {
        return Err(ExtractError::Invalid(
            "Signal master secret is shorter than its MAC".to_owned(),
        ));
    }
    let secret = crate::format::hex(secret);
    let mac = &secret[secret.len() - 40..];

    Ok(Some(Signal {
        version: 1,
        iterations,
        salt,
        digest,
        data: format!("{secret}${mac}"),
    }))
}

fn parse(artifact: &Artifact) -> Result<Vec<Signal>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("Signal preferences are not UTF-8".to_owned()))?;
    let document = roxmltree::Document::parse(text).map_err(|error| {
        ExtractError::Invalid(format!("invalid Signal preferences XML: {error}"))
    })?;

    let mut hashes = Vec::new();
    for map in document
        .descendants()
        .filter(|node| node.is_element() && node.has_tag_name("map"))
    {
        if let Some(hash) = record(map)? {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no Signal password record found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for SignalExtractor {
    fn slug(&self) -> &'static str {
        Signal::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("Signal Android secure preferences"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
