//! 1Password agilekeychain, rendered as `<iterations>:<salt>:<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// 1Password agilekeychain hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "1Password, agilekeychain",
    slug = "onepassword-agile",
    hashcat = [6600],
)]
pub struct OnepasswordAgile {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Data
    #[field(role = ciphertext, encoding = hex)]
    pub data: Vec<u8>,
}

impl Parse for OnepasswordAgile {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 3)?;
        Ok(Self {
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "invalid 1Password iteration count",
                )
            })?,
            salt: fields[1].0.to_owned(),
            data: parse::decode_hex(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for OnepasswordAgile {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            self.iterations,
            self.salt,
            crate::format::hex(&self.data)
        )
    }
}
