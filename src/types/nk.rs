//! NK hashes, rendered as `$nk$*<data>*#<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NK hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "NK", slug = "nk", hashcat = [], john = ["nk"])]
pub struct Nk {
    /// Encrypted data.
    #[field(role = salt, encoding = ascii)]
    pub data: String,

    /// Digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Nk {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$nk$*", 0)?;
        let (data, digest, digest_offset) = parse::split_once(rest, '*', 5)?;
        let digest = digest.strip_prefix('#').ok_or_else(|| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                digest_offset,
                "expected a `#` before the digest",
            )
        })?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing NK digest",
            ));
        }
        Ok(Self {
            data: data.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Nk {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$nk$*{}*#{}", self.data, self.digest)
    }
}
