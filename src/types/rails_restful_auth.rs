//! Ruby on Rails Restful Auth (one round, no sitekey), rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Ruby on Rails Restful Auth (one round, no sitekey) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Ruby on Rails Restful Auth (one round, no sitekey)",
    slug = "rails-restful-auth",
    hashcat = [27200],
)]
pub struct RailsRestfulAuth {
    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// 20-byte salt or seed
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 20],
}

impl Parse for RailsRestfulAuth {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, 0, "digest")?,
            salt: parse::decode_hex_field::<20>(salt, salt_offset, "salt")?,
        })
    }
}

impl Render for RailsRestfulAuth {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(self.salt)
        )
    }
}
