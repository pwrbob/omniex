//! RACF, rendered as a salted DES crypt hash.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RACF password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RACF",
    slug = "racf",
    hashcat = [8500], john = ["RACF"],
)]
pub struct Racf {
    /// Salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 8-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Racf {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$racf$*", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '*', 7)?;
        if salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                7,
                "RACF salt must be at most eight characters",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<8>(digest, 7 + digest_offset, "digest")?,
        })
    }
}

impl Render for Racf {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$racf$*{}*{}",
            self.salt,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
