//! OpenSSL `enc` salted payload extraction.
//!
//! The OpenSSL salted envelope records only the salt and ciphertext. The cipher
//! and digest are command-line choices, so this extractor requires an explicit
//! extractor selection and assumes the OpenSSL 1.1 and later defaults
//! (AES-256-CBC with SHA-256) unless `openssl-cipher` and `openssl-digest`
//! members provide the original values.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, CompanionSpec, ExtractError, Extracted, Extractor, Probe};
use crate::types::OpensslEnc;
use crate::{HashType, HashValue};

pub struct OpensslEncExtractor;

const SALTED_PREFIX: &[u8] = b"Salted__";
const DEFAULT_CIPHER: u8 = 0;
const DEFAULT_DIGEST: u8 = 2;

fn decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(b"Salted__") {
        return Some(data.to_vec());
    }
    let compact = data
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    STANDARD.decode(compact).ok()
}

fn member_parameter(artifact: &Artifact, name: &str) -> Result<Option<u8>, ExtractError> {
    let Some(source) = artifact.member(name) else {
        return Ok(None);
    };
    let data = source
        .read_all()
        .map_err(|error| ExtractError::Invalid(format!("cannot read {name} parameter: {error}")))?;
    let text = std::str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid(format!("{name} parameter is not text")))?;
    text.trim()
        .parse::<u8>()
        .map(Some)
        .map_err(|_| ExtractError::Invalid(format!("{name} parameter is not a number")))
}

fn parameters(artifact: &Artifact) -> Result<(u8, u8), ExtractError> {
    Ok((
        member_parameter(artifact, "openssl-cipher")?.unwrap_or(DEFAULT_CIPHER),
        member_parameter(artifact, "openssl-digest")?.unwrap_or(DEFAULT_DIGEST),
    ))
}

fn parse(artifact: &Artifact) -> Result<OpensslEnc, ExtractError> {
    let raw = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let data = decode(&raw)
        .ok_or_else(|| ExtractError::Unsupported("not an OpenSSL enc salted payload".to_owned()))?;
    if !data.starts_with(SALTED_PREFIX) {
        return Err(ExtractError::Unsupported(
            "not an OpenSSL enc salted payload".to_owned(),
        ));
    }
    if data.len() < 32 {
        return Err(ExtractError::Invalid(
            "OpenSSL enc payload is too short".to_owned(),
        ));
    }
    let (cipher, digest) = parameters(artifact)?;
    if cipher > 1 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported OpenSSL cipher {cipher}"
        )));
    }
    if digest > 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported OpenSSL digest {digest}"
        )));
    }
    let salt = &data[8..16];
    let ciphertext = &data[16..];
    let (last_chunk, inlined) = if ciphertext.len() <= 16 {
        (ciphertext, "1")
    } else {
        (&data[data.len() - 32..], "0")
    };

    let mut fields = format!(
        "{cipher}${digest}$8${}${}${inlined}",
        crate::format::hex(salt),
        crate::format::hex(last_chunk)
    );
    if inlined == "0" {
        let inline_data = &data[16..data.len().min(16 * 17)];
        fields.push_str(&format!(
            "${}${}",
            inline_data.len(),
            crate::format::hex(inline_data)
        ));
    }
    fields.push_str("$0");

    Ok(OpensslEnc { fields })
}

const COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional("openssl-cipher", "OpenSSL cipher byte; defaults to 1"),
    CompanionSpec::optional("openssl-digest", "OpenSSL digest byte; defaults to 6"),
];

impl Extractor for OpensslEncExtractor {
    fn companions(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn slug(&self) -> &'static str {
        OpensslEnc::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let raw = match artifact.primary().read_all() {
            Ok(raw) if !raw.is_empty() => raw,
            _ => return Probe::No,
        };
        let Some(data) = decode(&raw) else {
            return Probe::No;
        };
        if !data.starts_with(SALTED_PREFIX) {
            return Probe::No;
        }
        if data.len() < 32 {
            return Probe::maybe("truncated OpenSSL enc salted payload");
        }
        match parameters(artifact) {
            Ok(_) => {
                Probe::maybe("OpenSSL enc salted payload does not record its cipher or digest")
            }
            Err(error) => Probe::maybe(error.to_string()),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
