//! Legacy VeraCrypt headers, rendered as the raw 512-byte header in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Legacy VeraCrypt volume headers.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "VeraCrypt (legacy)",
    slug = "veracrypt-legacy",
    hashcat = [13711, 13712, 13713, 13721, 13722, 13723, 13731, 13732, 13733, 13741, 13742, 13743, 13751, 13752, 13753, 13761, 13762, 13763, 13771, 13772, 13773, 13781, 13782, 13783],
)]
pub struct VeraCryptLegacy {
    /// The 64-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 64],

    /// The 448-byte encrypted key data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 448],
}

impl Parse for VeraCryptLegacy {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 1024 {
            return Err(parse::error(
                crate::ParseErrorKind::InvalidLength,
                input.len(),
                "legacy VeraCrypt header must be 1024 hexadecimal digits",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<64>(&input[..128], 0, "salt")?,
            data: parse::decode_hex_field::<448>(&input[128..], 128, "data")?,
        })
    }
}

impl Render for VeraCryptLegacy {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.data)
        )
    }
}
