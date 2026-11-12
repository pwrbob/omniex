//! Oracle O5LOGON hashes, rendered as `$o5logon$<data>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Oracle O5LOGON hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Oracle O5LOGON", slug = "o5logon", hashcat = [], john = ["o5logon"])]
pub struct O5logon {
    /// Server data
    #[field(role = salt, encoding = ascii)]
    pub data: String,

    /// Client digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for O5logon {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$o5logon$", 0)?;
        let (data, digest, digest_offset) = parse::split_once(rest, '*', 9)?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing O5LOGON digest",
            ));
        }
        Ok(Self {
            data: data.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for O5logon {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$o5logon${}*{}", self.data, self.digest)
    }
}
