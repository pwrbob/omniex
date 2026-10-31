//! 1Password cloudkeychain, rendered as `<digest>:<salt>:<iterations>:<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// 1Password cloudkeychain hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "1Password, cloudkeychain",
    slug = "onepassword-cloud",
    hashcat = [8200],
)]
pub struct OnepasswordCloud {
    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for OnepasswordCloud {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 4)?;
        Ok(Self {
            digest: parse::decode_hex_field::<32>(fields[0].0, fields[0].1, "digest")?,
            salt: parse::decode_hex(fields[1].0, fields[1].1)?,
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid 1Password iteration count",
                )
            })?,
            data: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for OnepasswordCloud {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.salt),
            self.iterations,
            crate::format::hex(&self.data)
        )
    }
}
