//! Radmin3, rendered as `$radmin3$<username>*<salt>*<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Radmin3 password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Radmin3",
    slug = "radmin3",
    hashcat = [29200],
)]
pub struct Radmin3 {
    /// Username bytes, serialized as hex.
    #[field(role = username, encoding = hex)]
    pub username: Vec<u8>,

    /// The 32-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 32],

    /// Hexadecimal ciphertext.
    #[field(role = ciphertext, encoding = hex)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Radmin3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$radmin3$", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        Ok(Self {
            username: parse::decode_hex(fields[0].0, fields[0].1)?,
            salt: parse::decode_hex_field::<32>(fields[1].0, fields[1].1, "salt")?,
            ciphertext: parse::decode_hex(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for Radmin3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$radmin3${}*{}*{}",
            crate::format::hex(&self.username),
            crate::format::hex(self.salt),
            crate::format::hex(&self.ciphertext)
        )
    }
}
