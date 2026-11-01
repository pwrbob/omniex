//! Legacy TrueCrypt headers, rendered as the raw 512-byte header in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Legacy TrueCrypt volume headers.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "TrueCrypt (legacy)",
    slug = "truecrypt-legacy",
    hashcat = [6211, 6212, 6213, 6221, 6222, 6223, 6231, 6232, 6233, 6241, 6242, 6243],
)]
pub struct TrueCryptLegacy {
    /// The 64-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 64],

    /// The 448-byte encrypted key data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 448],
}

impl Parse for TrueCryptLegacy {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 1024 {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidLength,
                input.len(),
                "legacy TrueCrypt header must be 1024 hexadecimal digits",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<64>(&input[..128], 0, "salt")?,
            data: parse::decode_hex_field::<448>(&input[128..], 128, "data")?,
        })
    }
}

impl Render for TrueCryptLegacy {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.data)
        )
    }
}
