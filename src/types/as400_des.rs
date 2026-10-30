//! AS/400 DES, rendered as a salted DES crypt hash.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AS/400 DES password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AS/400 DES",
    slug = "as400-des",
    hashcat = [8501],
)]
pub struct As400Des {
    /// Salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 8-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for As400Des {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$as400$des$*", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '*', 12)?;
        if salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                12,
                "AS/400 DES salt must be at most eight characters",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<8>(digest, 12 + digest_offset, "digest")?,
        })
    }
}

impl Render for As400Des {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$as400$des$*{}*{}",
            self.salt,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
