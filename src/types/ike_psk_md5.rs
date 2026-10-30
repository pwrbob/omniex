//! IKE-PSK MD5, rendered as its complete challenge-response string.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// IKE-PSK MD5 challenge-response.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "IKE-PSK MD5",
    slug = "ike-psk-md5",
    hashcat = [5300],
)]
pub struct IkePskMd5 {
    /// Complete IKE-PSK MD5 string.
    #[field(role = ciphertext, encoding = ascii)]
    pub blob: String,
}

impl Parse for IkePskMd5 {
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

impl Render for IkePskMd5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.blob.clone()
    }
}
