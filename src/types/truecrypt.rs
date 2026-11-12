//! TrueCrypt, rendered as `$truecrypt$<hex salt and encrypted key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// TrueCrypt volume hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "TrueCrypt",
    slug = "truecrypt",
    hashcat = [29311, 29312, 29313, 29321, 29322, 29323, 29331, 29332, 29333, 29341, 29342, 29343],
)]
pub struct TrueCrypt {
    /// 64-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 64],

    /// 448-byte encrypted key data
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 448],
}

impl Parse for TrueCrypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$truecrypt$", 0)?;
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

impl Render for TrueCrypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$truecrypt${}${}",
            crate::format::hex(self.salt),
            crate::format::hex(self.data)
        )
    }
}
