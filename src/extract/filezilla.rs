//! FileZilla Server configuration extraction.

use std::str;

use roxmltree::Document;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::parse;
use crate::types::FilezillaServer;
use crate::{HashType, HashValue};

pub struct FileZillaServerExtractor;

impl Extractor for FileZillaServerExtractor {
    fn slug(&self) -> &'static str {
        FilezillaServer::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let mut prefix = [0; 4096];
        match artifact.primary().read_at(0, &mut prefix) {
            Ok(read) => {
                let text = String::from_utf8_lossy(&prefix[..read]);
                if text.contains("<FileZillaServer") {
                    Probe::yes("FileZilla Server XML root")
                } else {
                    Probe::No
                }
            }
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let text = str::from_utf8(&data).map_err(|_| {
            ExtractError::Invalid("FileZilla configuration is not UTF-8".to_owned())
        })?;
        let document = Document::parse(text)
            .map_err(|error| ExtractError::Invalid(format!("invalid FileZilla XML: {error}")))?;

        let mut hashes = Vec::new();
        for user in document
            .descendants()
            .filter(|node| node.is_element() && node.has_tag_name("User"))
        {
            let mut digest = None;
            let mut salt = None;
            for option in user
                .children()
                .filter(|node| node.is_element() && node.has_tag_name("Option"))
            {
                match option.attribute("Name") {
                    Some("Pass") => digest = option.text(),
                    Some("Salt") => salt = option.text(),
                    _ => {}
                }
            }

            let Some(digest) = digest else {
                continue;
            };
            let digest = digest.trim().to_ascii_lowercase();
            let Some(salt) = salt else {
                continue;
            };
            if digest.len() != 128 {
                continue;
            }
            let digest = parse::decode_hex_field::<64>(&digest, 0, "digest").map_err(|error| {
                ExtractError::Invalid(format!("invalid FileZilla digest: {error}"))
            })?;
            hashes.push(Box::new(FilezillaServer {
                digest,
                salt: crate::format::hex(salt.trim().as_bytes()),
            }) as Box<dyn HashValue>);
        }

        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no supported FileZilla Server hashes found".to_owned(),
            ));
        }
        Ok(hashes)
    }
}
