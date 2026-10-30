//! Cisco-IOS type 4, rendered as its base64 signature.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Cisco-IOS type 4 (SHA-256) password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Cisco-IOS type 4",
    slug = "cisco-ios4",
    hashcat = [5700],
)]
pub struct CiscoIos4 {
    /// Base64 signature.
    #[field(role = digest, encoding = ascii)]
    pub signature: String,
}

impl Parse for CiscoIos4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 43 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Cisco-IOS type 4 signature must be 43 characters",
            ));
        }
        parse::decode_base64(input, 0)?;
        Ok(Self {
            signature: input.to_owned(),
        })
    }
}

impl Render for CiscoIos4 {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.signature.clone()
    }
}
