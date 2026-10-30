//! VeraCrypt, rendered as `$veracrypt$<hex salt and encrypted key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// VeraCrypt volume hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "VeraCrypt",
    slug = "veracrypt",
    hashcat = [29411, 29412, 29413, 29421, 29422, 29423, 29431, 29432, 29433, 29441, 29442, 29443, 29451, 29452, 29453, 29461, 29462, 29463, 29471, 29472, 29473, 29481, 29482, 29483, 29491, 29492, 29493],
)]
pub struct VeraCrypt {
    /// The 64-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 64],

    /// The 448-byte encrypted key data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 448],
}

impl Parse for VeraCrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$veracrypt$", 0)?;
        let Some(separator) = rest.find('$') else {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "expected `$` between salt and encrypted key data",
            ));
        };
        let salt = &rest[..separator];
        let data = &rest[separator + 1..];
        if salt.len() != 128 || data.len() != 896 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "salt and encrypted key data have fixed lengths",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<64>(salt, 0, "salt")?,
            data: parse::decode_hex_field::<448>(data, separator + 1, "data")?,
        })
    }
}

impl Render for VeraCrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$veracrypt${}${}",
            crate::format::hex(self.salt),
            crate::format::hex(self.data)
        )
    }
}
