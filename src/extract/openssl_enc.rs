//! OpenSSL `enc` salted payload extraction.
//!
//! The OpenSSL salted envelope records only the salt and ciphertext. The cipher
//! and digest are command-line choices, so extraction assumes the OpenSSL 1.1
//! and later defaults (AES-256-CBC with SHA-256) unless `--opt cipher=...` or
//! `--opt digest=...` provide the original values. Only AES block sizes are
//! serialized: John's `openssl-enc` format supports AES-128 and AES-256.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{Artifact, ExtractError, Extracted, Extractor, OptionSpec, Probe, ReadAt};
use crate::types::OpensslEnc;
use crate::{HashType, HashValue};

pub struct OpensslEncExtractor;

const SALTED_PREFIX: &[u8] = b"Salted__";
const SALTED_HEADER: u64 = 16;
const INLINE_DATA: u64 = 16 * 16;
const LAST_CHUNK: u64 = 32;
const MAX_BASE64: u64 = 16 * 1024 * 1024;
const DEFAULT_CIPHER: u8 = 0;
const DEFAULT_DIGEST: u8 = 2;

const CIPHERS: &[(&str, u8)] = &[("aes-256", 0), ("aes-128", 1)];
const DIGESTS: &[(&str, u8)] = &[("md5", 0), ("sha1", 1), ("sha256", 2)];

const OPTIONS: &[OptionSpec] = &[
    OptionSpec::value(
        "cipher",
        "AES cipher: `aes-256` (0) or `aes-128` (1); default `aes-256`",
    ),
    OptionSpec::value(
        "digest",
        "KDF digest: `md5` (0), `sha1` (1), or `sha256` (2); default `sha256`",
    ),
];

fn parameter(
    artifact: &Artifact,
    name: &str,
    choices: &[(&str, u8)],
    default: u8,
) -> Result<u8, ExtractError> {
    let Some(text) = artifact.option(name) else {
        return Ok(default);
    };
    let text = text.trim().to_ascii_lowercase();
    if let Some(value) = choices
        .iter()
        .find_map(|(label, value)| (*label == text).then_some(*value))
    {
        return Ok(value);
    }
    if let Ok(value) = text.parse::<u8>() {
        if let Some(value) = choices
            .iter()
            .find_map(|(_, candidate)| (*candidate == value).then_some(value))
        {
            return Ok(value);
        }
    }
    Err(ExtractError::Unsupported(format!(
        "unsupported OpenSSL {name} `{text}`; expected {}",
        choices
            .iter()
            .map(|(label, _)| *label)
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn parameters(artifact: &Artifact) -> Result<(u8, u8), ExtractError> {
    Ok((
        parameter(artifact, "cipher", CIPHERS, DEFAULT_CIPHER)?,
        parameter(artifact, "digest", DIGESTS, DEFAULT_DIGEST)?,
    ))
}

struct Payload {
    head: Vec<u8>,
    tail: Vec<u8>,
    length: u64,
}

fn read_range(source: &dyn ReadAt, offset: u64, length: u64) -> Result<Vec<u8>, ExtractError> {
    let mut data = vec![0; usize::try_from(length).unwrap_or(usize::MAX)];
    source
        .read_exact_at(offset, &mut data)
        .map_err(|error| ExtractError::Invalid(format!("cannot read OpenSSL payload: {error}")))?;
    Ok(data)
}

fn envelope(artifact: &Artifact) -> Result<Payload, ExtractError> {
    let source = artifact.primary();
    let length = source.len();
    if length < SALTED_HEADER + 16 {
        return Err(ExtractError::Invalid(
            "OpenSSL enc payload is too short".to_owned(),
        ));
    }
    let head_length = length.min(SALTED_HEADER + INLINE_DATA);
    let head = read_range(source, 0, head_length)?;
    if head.starts_with(SALTED_PREFIX) {
        let tail = if length >= LAST_CHUNK {
            read_range(source, length - LAST_CHUNK, LAST_CHUNK)?
        } else {
            head.clone()
        };
        return Ok(Payload { head, tail, length });
    }

    if length > MAX_BASE64 {
        return Err(ExtractError::Unsupported(
            "base64 OpenSSL enc payload is too large; decode it before extraction".to_owned(),
        ));
    }
    let raw = source
        .read_all()
        .map_err(|error| ExtractError::Invalid(format!("cannot read artifact: {error}")))?;
    let compact = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let data = STANDARD
        .decode(&compact)
        .map_err(|_| ExtractError::Unsupported("not an OpenSSL enc salted payload".to_owned()))?;
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
    let head = data[..data.len().min((SALTED_HEADER + INLINE_DATA) as usize)].to_vec();
    let tail = data[data.len() - (LAST_CHUNK as usize)..].to_vec();
    Ok(Payload {
        head,
        tail,
        length: data.len() as u64,
    })
}

fn parse(artifact: &Artifact) -> Result<OpensslEnc, ExtractError> {
    let payload = envelope(artifact)?;
    let ciphertext = payload.length - SALTED_HEADER;
    if ciphertext % 16 != 0 {
        return Err(ExtractError::Unsupported(format!(
            "OpenSSL ciphertext is {ciphertext} bytes, not a multiple of the AES block size; \
             John's openssl-enc format only serializes AES-128 and AES-256"
        )));
    }
    let (cipher, digest) = parameters(artifact)?;
    let salt = &payload.head[8..16];
    let (last_chunk, inlined) = if ciphertext <= 16 {
        (&payload.head[16..16 + ciphertext as usize], true)
    } else {
        (&payload.tail[..], false)
    };

    let mut fields = format!(
        "{cipher}${digest}$8${}${}${}",
        crate::format::hex(salt),
        crate::format::hex(last_chunk),
        if inlined { "1" } else { "0" }
    );
    if !inlined {
        let inline = &payload.head[16..payload.head.len().min(16 + INLINE_DATA as usize)];
        fields.push_str(&format!("${}${}", inline.len(), crate::format::hex(inline)));
    }
    fields.push_str("$0");

    Ok(OpensslEnc { fields })
}

impl Extractor for OpensslEncExtractor {
    fn slug(&self) -> &'static str {
        OpensslEnc::SLUG
    }

    fn options(&self) -> &'static [OptionSpec] {
        OPTIONS
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let source = artifact.primary();
        let length = source.len();
        if length < 16 {
            return Probe::No;
        }
        let mut head = [0u8; 16];
        if source.read_exact_at(0, &mut head).is_err() {
            return Probe::No;
        }
        if head.starts_with(SALTED_PREFIX) {
            return if length < 32 {
                Probe::maybe("truncated OpenSSL enc salted payload")
            } else {
                Probe::yes("OpenSSL enc salted envelope")
            };
        }

        let mut raw = [0u8; 64];
        let Ok(read) = source.read_at(0, &mut raw) else {
            return Probe::No;
        };
        let compact = raw[..read]
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let usable = compact.len() / 4 * 4;
        if usable >= 12
            && STANDARD
                .decode(&compact[..usable])
                .is_ok_and(|decoded| decoded.starts_with(SALTED_PREFIX))
        {
            return Probe::yes("OpenSSL enc salted envelope");
        }
        Probe::No
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
