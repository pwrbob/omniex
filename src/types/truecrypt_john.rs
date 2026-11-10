//! John OpenCL TrueCrypt hashes, rendered as `<variant>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// TrueCrypt header in John's OpenCL serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "TrueCrypt header",
    slug = "truecrypt-header",
    john = ["TrueCrypt-opencl"],
)]
pub struct TrueCryptJohn {
    /// Hash variant prefix, such as `truecrypt_RIPEMD_160`.
    #[field(role = other, encoding = ascii)]
    pub variant: String,

    /// Raw TrueCrypt header data.
    #[field(role = ciphertext, encoding = hex)]
    pub data: [u8; 512],
}

impl Parse for TrueCryptJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (variant, rest, offset) = parse::split_once(input, '$', 0)?;
        if !matches!(
            variant,
            "truecrypt_RIPEMD_160" | "truecrypt_SHA512" | "truecrypt_Whirlpool"
        ) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "unsupported TrueCrypt John variant",
            ));
        }
        Ok(Self {
            variant: variant.to_owned(),
            data: parse::decode_hex_field::<512>(rest, offset, "data")?,
        })
    }
}

impl Render for TrueCryptJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.variant, crate::format::hex(self.data))
    }
}
