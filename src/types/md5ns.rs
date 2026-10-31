//! md5ns hashes, rendered as `<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Netscape / md5ns hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "md5ns", slug = "md5ns", hashcat = [], john = ["md5ns"])]
pub struct Md5ns {
    /// User name.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Encoded digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Md5ns {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (username, digest, digest_offset) = parse::split_once(input, '$', 0)?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing md5ns digest",
            ));
        }
        Ok(Self {
            username: username.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Md5ns {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.username, self.digest)
    }
}
