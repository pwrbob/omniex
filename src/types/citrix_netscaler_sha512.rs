//! Citrix NetScaler SHA2-512, rendered as `2<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Citrix NetScaler SHA2-512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Citrix NetScaler SHA512",
    slug = "citrix-netscaler-sha512",
    hashcat = [22200],
)]
pub struct CitrixNetScalerSha512 {
    /// 8-character salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 64-byte SHA2-512 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for CitrixNetScalerSha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 137 || !input.starts_with('2') {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Citrix NetScaler SHA512 values are 137 characters starting with `2`",
            ));
        }
        Ok(Self {
            salt: input[1..9].to_owned(),
            digest: parse::decode_hex_field::<64>(&input[9..], 9, "digest")?,
        })
    }
}

impl Render for CitrixNetScalerSha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("2{}{}", self.salt, crate::format::hex(self.digest))
    }
}
