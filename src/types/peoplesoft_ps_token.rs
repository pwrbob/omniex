//! PeopleSoft PS_TOKEN, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PeopleSoft PS_TOKEN values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PeopleSoft PS_TOKEN",
    slug = "peoplesoft-ps-token",
    hashcat = [13500],
)]
pub struct PeoplesoftPsToken {
    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for PeoplesoftPsToken {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "salt must not contain `:`",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for PeoplesoftPsToken {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
