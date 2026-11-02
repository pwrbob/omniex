//! RACF KDFAES passphrase record extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::RacfKdfaesPassphrase;
use crate::{HashType, HashValue, Parse, ParseOptions};

pub struct RacfKdfaesPassphraseExtractor;

const PREFIX: &str = "$racf-kdfaes$*";

fn header(value: &str) -> Option<&str> {
    value.strip_prefix(PREFIX)?.split('*').nth(1)
}

fn passphrase_header_shape(header: &str) -> bool {
    header.len() == 32 && header.starts_with("E7D7E66D0001") && header.as_bytes()[12] == b'4'
}

fn passphrase_header(header: &str) -> bool {
    passphrase_header_shape(header) && header.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn passphrase(value: &str) -> Option<RacfKdfaesPassphrase> {
    let hash = RacfKdfaesPassphrase::parse(value, &ParseOptions::default()).ok()?;
    passphrase_header(&hash.parameters).then_some(hash)
}

fn parse(artifact: &Artifact) -> Result<Vec<RacfKdfaesPassphrase>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("RACF record export is not UTF-8".to_owned()))?;

    let mut hashes = Vec::new();
    let mut malformed = None;
    for (index, _) in text.match_indices(PREFIX) {
        let rest = &text[index..];
        let end = rest
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | ',' | ';' | '<' | '>')
            })
            .unwrap_or(rest.len());
        let candidate = &rest[..end];
        if let Some(hash) = passphrase(candidate) {
            hashes.push(hash);
        } else if header(candidate).is_some_and(passphrase_header_shape) {
            malformed = Some(candidate.to_owned());
        }
    }

    if let Some(record) = malformed {
        return Err(ExtractError::Invalid(format!(
            "invalid RACF KDFAES passphrase record `{record}`"
        )));
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no RACF KDFAES passphrase record found".to_owned(),
        ));
    }
    Ok(hashes)
}

impl Extractor for RacfKdfaesPassphraseExtractor {
    fn slug(&self) -> &'static str {
        RacfKdfaesPassphrase::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("RACF KDFAES passphrase record"),
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
