//! SQLCipher database header extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Sqlcipher;
use crate::{HashType, HashValue};

pub struct SqlcipherExtractor;

const HEADER_SIZE: usize = 96;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

fn member_text(artifact: &Artifact, name: &str) -> Option<String> {
    let data = artifact.member(name)?.read_all().ok()?;
    Some(str::from_utf8(&data).ok()?.trim().to_owned())
}

fn parameters(artifact: &Artifact) -> Result<(u8, u32), ExtractError> {
    if let Some(preset) = member_text(artifact, "sqlcipher-preset") {
        return match preset.as_str() {
            "1" => Ok((1, 64_000)),
            "2" => Ok((3, 256_000)),
            _ => Err(ExtractError::Invalid(format!(
                "unknown SQLCipher preset `{preset}`"
            ))),
        };
    }

    let kind = member_text(artifact, "sqlcipher-type").ok_or_else(|| {
        ExtractError::Unsupported(
            "SQLCipher KDF type is not encoded in the database; provide a \
             `sqlcipher-type` companion or a `sqlcipher-preset` companion"
                .to_owned(),
        )
    })?;
    let iterations = member_text(artifact, "sqlcipher-iterations").ok_or_else(|| {
        ExtractError::Unsupported(
            "SQLCipher iteration count is not encoded in the database; provide a \
             `sqlcipher-iterations` companion"
                .to_owned(),
        )
    })?;

    let kind = kind
        .parse::<u8>()
        .ok()
        .filter(|kind| (1..=3).contains(kind))
        .ok_or_else(|| ExtractError::Invalid(format!("invalid SQLCipher KDF type `{kind}`")))?;
    let iterations = iterations
        .parse::<u32>()
        .ok()
        .filter(|iterations| *iterations >= 1)
        .ok_or_else(|| {
            ExtractError::Invalid(format!("invalid SQLCipher iteration count `{iterations}`"))
        })?;
    Ok((kind, iterations))
}

fn parse(artifact: &Artifact) -> Result<Sqlcipher, ExtractError> {
    if artifact.primary().len() < HEADER_SIZE as u64 {
        return Err(ExtractError::Unsupported(
            "SQLCipher database is shorter than a page header".to_owned(),
        ));
    }
    let mut header = [0; HEADER_SIZE];
    artifact
        .primary()
        .read_exact_at(0, &mut header)
        .map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
    if &header[..16] == SQLITE_MAGIC {
        return Err(ExtractError::Unsupported(
            "database is plaintext SQLite, not SQLCipher".to_owned(),
        ));
    }
    if artifact.primary().len() % 512 != 0 {
        return Err(ExtractError::Unsupported(
            "database length is not a multiple of a SQLCipher page size".to_owned(),
        ));
    }

    let (version, iterations) = parameters(artifact)?;
    let salt = crate::format::hex(&header[..16]);
    let iv = header[64..80].try_into().expect("fixed SQLCipher IV range");
    let digest = header[80..96]
        .try_into()
        .expect("fixed SQLCipher digest range");
    Ok(Sqlcipher {
        version,
        iterations,
        salt,
        iv,
        digest,
    })
}

impl Extractor for SqlcipherExtractor {
    fn slug(&self) -> &'static str {
        Sqlcipher::SLUG
    }

    fn exact(&self) -> bool {
        false
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let len = artifact.primary().len();
        if len < HEADER_SIZE as u64 || len % 512 != 0 {
            return Probe::No;
        }
        let mut magic = [0; 16];
        match artifact.primary().read_exact_at(0, &mut magic) {
            Ok(()) if &magic != SQLITE_MAGIC => {
                Probe::maybe("SQLCipher database page layout; KDF parameters are external")
            }
            Ok(()) => Probe::No,
            Err(error) => Probe::maybe(format!("cannot read artifact: {error}")),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
