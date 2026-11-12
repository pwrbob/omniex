//! Android FDE Samsung DEK hashes, rendered as `<salt><digest><iv>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Android FDE Samsung DEK hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Android FDE (Samsung DEK)",
    slug = "android-fde-samsung",
    hashcat = [12900]
)]
pub struct AndroidFdeSamsung {
    /// 48-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// 16-byte IV
    #[field(role = other, encoding = hex)]
    pub iv: [u8; 16],
}

impl Parse for AndroidFdeSamsung {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 160 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Android Samsung DEK values are 160 hex characters",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex(&input[..64], 0)?,
            digest: parse::decode_hex_field::<32>(&input[64..128], 64, "digest")?,
            iv: parse::decode_hex_field::<16>(&input[128..], 128, "iv")?,
        })
    }
}

impl Render for AndroidFdeSamsung {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}{}",
            crate::format::hex(&self.salt),
            crate::format::hex(self.digest),
            crate::format::hex(self.iv)
        )
    }
}
