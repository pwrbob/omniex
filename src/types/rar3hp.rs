//! RAR3 header encryption hashes, rendered as `$RAR3$*0*<salt>*<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RAR3 header encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "RAR3-hp", slug = "rar3hp", hashcat = [12500], john = ["rar"])]
pub struct Rar3hp {
    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 16-byte encrypted header
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 16],
}

impl Parse for Rar3hp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$RAR3$*0*", 0)?;
        let fields = parse::split_fields(rest, '*', 2)?;
        Ok(Self {
            salt: parse::decode_hex_field::<8>(fields[0].0, 9, "salt")?,
            data: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "data")?,
        })
    }
}

impl Render for Rar3hp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$RAR3$*0*{}*{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.data)
        )
    }
}
