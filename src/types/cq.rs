//! CQ hashes, rendered as `$cq$<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// CQ hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "cq", slug = "cq", hashcat = [], john = ["cq"])]
pub struct Cq {
    /// User name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// 8-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Cq {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cq$", 0)?;
        let (username, digest, digest_offset) = parse::split_once(rest, '$', 4)?;
        if digest.len() != 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "CQ digests are eight characters",
            ));
        }
        Ok(Self {
            username: username.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Cq {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$cq${}${}", self.username, self.digest)
    }
}
