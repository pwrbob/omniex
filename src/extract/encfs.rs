//! EncFS configuration extraction.

use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Encfs;
use crate::{HashType, HashValue};

pub struct EncfsExtractor;

struct Values {
    key_size: u32,
    iterations: u32,
    salt_len: usize,
    salt: Vec<u8>,
    data_len: usize,
    data: Vec<u8>,
}

fn text<'a>(document: &'a Document, tag: &str) -> Option<&'a str> {
    document
        .descendants()
        .find(|node| node.is_element() && node.has_tag_name(tag))
        .and_then(|node: Node<'a, 'a>| node.text())
        .map(str::trim)
}

fn values(document: &Document) -> Result<Values, ExtractError> {
    let cipher = text(document, "name")
        .ok_or_else(|| ExtractError::Invalid("missing EncFS cipher name".to_owned()))?;
    if !cipher.to_ascii_uppercase().contains("AES") {
        return Err(ExtractError::Unsupported(format!(
            "unsupported EncFS cipher `{cipher}`"
        )));
    }
    let number = |tag: &str| -> Result<u32, ExtractError> {
        text(document, tag)
            .ok_or_else(|| ExtractError::Invalid(format!("missing EncFS {tag}")))?
            .parse::<u32>()
            .map_err(|_| ExtractError::Invalid(format!("invalid EncFS {tag}")))
    };
    let key_size = number("keySize")?;
    let iterations = number("kdfIterations")?;
    let salt_len = number("saltLen")? as usize;
    let data_len = number("encodedKeySize")? as usize;

    let decode = |tag: &str| -> Result<Vec<u8>, ExtractError> {
        let value = text(document, tag)
            .ok_or_else(|| ExtractError::Invalid(format!("missing EncFS {tag}")))?;
        STANDARD
            .decode(value)
            .map_err(|_| ExtractError::Invalid(format!("invalid EncFS {tag} base64")))
    };
    let salt = decode("saltData")?;
    let data = decode("encodedKeyData")?;
    if salt.len() != salt_len {
        return Err(ExtractError::Invalid(
            "EncFS salt length does not match saltLen".to_owned(),
        ));
    }
    if data.len() != data_len {
        return Err(ExtractError::Invalid(
            "EncFS key length does not match encodedKeySize".to_owned(),
        ));
    }

    Ok(Values {
        key_size,
        iterations,
        salt_len,
        salt,
        data_len,
        data,
    })
}

fn parse(artifact: &Artifact) -> Result<Encfs, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("EncFS configuration is not UTF-8".to_owned()))?;
    let document = Document::parse(text)
        .map_err(|error| ExtractError::Invalid(format!("invalid EncFS XML: {error}")))?;
    let values = values(&document)?;
    Ok(Encfs {
        fields: format!(
            "{}*{}*0*{}*{}*{}*{}",
            values.key_size,
            values.iterations,
            values.salt_len,
            crate::format::hex(&values.salt),
            values.data_len,
            crate::format::hex(&values.data)
        ),
    })
}

impl Extractor for EncfsExtractor {
    fn slug(&self) -> &'static str {
        Encfs::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("EncFS configuration"),
            Err(ExtractError::Invalid(_) | ExtractError::Unsupported(_)) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
