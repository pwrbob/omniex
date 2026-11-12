//! Besder Authentication MD5, rendered as an eight-character digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Besder Authentication MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Besder Authentication MD5",
    slug = "besder-md5",
    hashcat = [24901],
)]
pub struct BesderMd5 {
    /// 8-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for BesderMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Besder Authentication MD5 digests are eight characters",
            ));
        }
        Ok(Self {
            digest: input.to_owned(),
        })
    }
}

impl Render for BesderMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.digest.clone()
    }
}
