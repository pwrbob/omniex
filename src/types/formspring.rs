//! FormSpring hashes, rendered as `<digest>$<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// FormSpring password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "FormSpring", slug = "formspring", hashcat = [], john = ["FormSpring"])]
pub struct FormSpring {
    /// Digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Case-sensitive salt suffix
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for FormSpring {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, '$', 0)?;
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                salt_offset,
                "missing FormSpring salt",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for FormSpring {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}{}{}", crate::format::hex(self.digest), '$', self.salt)
    }
}
