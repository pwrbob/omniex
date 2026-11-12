//! MODX Evolution uncrypt, rendered as `uncrypt><digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MODX Evolution uncrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MODX Evolution (uncrypt)",
    slug = "modx-evolution",
    hashcat = [40007],
)]
pub struct ModxEvolution {
    /// 20-byte SHA1 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for ModxEvolution {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "uncrypt>", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, ':', 9)?;
        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                9 + salt_offset,
                "salt must not contain `:`",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 9, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for ModxEvolution {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("uncrypt>{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
