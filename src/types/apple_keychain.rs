//! Apple Keychain, rendered as `$keychain$*<salt>*<iv>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Apple Keychain hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Apple Keychain",
    slug = "apple-keychain",
    hashcat = [23100],
)]
pub struct AppleKeychain {
    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal IV.
    #[field(role = iv, encoding = hex)]
    pub iv: Vec<u8>,

    /// Hexadecimal encrypted data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for AppleKeychain {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$keychain$*", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            salt: parse::decode_hex(fields[0].0, fields[0].1)?,
            iv: parse::decode_hex(fields[1].0, fields[1].1)?,
            data: parse::decode_hex(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for AppleKeychain {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$keychain$*{}*{}*{}",
            crate::format::hex(&self.salt),
            crate::format::hex(&self.iv),
            crate::format::hex(&self.data)
        )
    }
}
