//! Citrix NetScaler SHA1, rendered as `1<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Citrix NetScaler SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Citrix NetScaler SHA1",
    slug = "citrix-netscaler-sha1",
    hashcat = [8100],
    john = ["Citrix_NS10"],
)]
pub struct CitrixNetScalerSha1 {
    /// Eight salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 20-byte SHA1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for CitrixNetScalerSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 49 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Citrix NetScaler SHA1 values are 49 characters",
            ));
        }
        if !input.starts_with('1') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected Citrix NetScaler signature `1`",
            ));
        }
        Ok(Self {
            salt: input[1..9].to_owned(),
            digest: parse::decode_hex_field::<20>(&input[9..], 9, "digest")?,
        })
    }
}

impl Render for CitrixNetScalerSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("1{}{}", self.salt, crate::format::hex(self.digest))
    }
}
