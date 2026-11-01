//! Artifact extraction into the same hash type instances used by parsing.

use std::fmt;

use crate::HashValue;

/// Hashes produced by one extractor.
pub type Extracted = Vec<Box<dyn HashValue>>;

/// One successful auto-detection result.
pub struct Detection {
    /// Extractor that recognized the artifact.
    pub extractor: &'static dyn Extractor,
    /// Hashes the extractor produced.
    pub hashes: Extracted,
}

/// One extractor for a hash type.
pub trait Extractor: Sync {
    /// Hash type slug this extractor produces.
    fn slug(&self) -> &'static str;

    /// Extract every matching hash from an artifact.
    fn extract(&self, data: &[u8]) -> Result<Extracted, ExtractError>;
}

/// A failure while extracting an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The artifact is not in a shape this extractor understands.
    Unsupported(String),
    /// The artifact is in the expected shape but is malformed.
    Invalid(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

mod gpg;

pub static EXTRACTORS: &[&dyn Extractor] = &[&gpg::GpgExtractor];

/// Returns the extractor registered for a slug.
#[must_use]
pub fn by_slug(slug: &str) -> Option<&'static dyn Extractor> {
    EXTRACTORS
        .iter()
        .copied()
        .find(|extractor| extractor.slug() == slug)
}

/// Tries every registered extractor and keeps the successful results.
#[must_use]
pub fn detect(data: &[u8]) -> Vec<Detection> {
    EXTRACTORS
        .iter()
        .filter_map(|extractor| {
            extractor.extract(data).ok().map(|hashes| Detection {
                extractor: *extractor,
                hashes,
            })
        })
        .collect()
}
