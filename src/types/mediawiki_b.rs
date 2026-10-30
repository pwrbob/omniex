//! MediaWiki B type, rendered as `$B$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MediaWiki B-type password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MediaWiki B",
    slug = "mediawiki-b",
    hashcat = [3711],
    john = ["MediaWiki"],
)]
pub struct MediaWikiB {
    /// Decimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for MediaWikiB {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$B$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 3)?;

        if salt.is_empty() || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                3,
                "MediaWiki salt must be decimal digits",
            ));
        }

        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for MediaWikiB {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("$B${}${}", self.salt, crate::format::hex(self.digest))
    }
}
