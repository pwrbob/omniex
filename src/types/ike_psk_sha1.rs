//! IKE-PSK SHA1, rendered as its complete challenge-response string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// IKE-PSK SHA1 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "IKE-PSK SHA1",
    slug = "ike-psk-sha1",
    hashcat = [5400],
)]
pub struct IkePskSha1 {
    /// Complete IKE-PSK SHA1 string.
    #[field(role = ciphertext, encoding = ascii)]
    pub blob: String,
}

impl Parse for IkePskSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if !input.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected an IKE-PSK field separator",
            ));
        }
        Ok(Self {
            blob: input.to_owned(),
        })
    }
}

impl Render for IkePskSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.blob.clone()
    }
}
