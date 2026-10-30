//! PHPS, rendered as `$PHPS$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PHPS password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PHPS",
    slug = "phps",
    hashcat = [2612],
    john = ["PHPS"],
)]
pub struct Phps {
    /// Decimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Phps {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$PHPS$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 6)?;

        if salt.is_empty() || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                6,
                "PHPS salt must be decimal digits",
            ));
        }

        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Phps {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$PHPS${}${}", self.salt, crate::format::hex(self.digest))
    }
}
