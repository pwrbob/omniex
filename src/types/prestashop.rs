//! PrestaShop, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PrestaShop salted MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PrestaShop",
    slug = "prestashop",
    hashcat = [40026],
)]
pub struct Prestashop {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Decimal salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Prestashop {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if !(56..=64).contains(&salt.len()) || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "PrestaShop salt must be 56 to 64 decimal digits",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Prestashop {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
