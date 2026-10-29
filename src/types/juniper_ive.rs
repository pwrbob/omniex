//! Juniper IVE, rendered as a single standard base64 blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Juniper IVE password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Juniper IVE",
    slug = "juniper-ive",
    hashcat = [501],
)]
pub struct JuniperIve {
    /// The base64-encoded ciphertext blob.
    #[field(role = ciphertext, encoding = ascii)]
    pub signature: String,
}

impl Parse for JuniperIve {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let decoded = parse::decode_base64(input, 0)?;
        if decoded.len() != 76 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Juniper IVE blob must decode to 76 bytes",
            ));
        }

        Ok(Self {
            signature: input.to_owned(),
        })
    }
}

impl Render for JuniperIve {
    fn render(&self, _opts: &RenderOptions) -> String {
        self.signature.clone()
    }
}
