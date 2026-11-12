//! Blockchain wallet second passwords, rendered as a base64 blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Blockchain wallet second-password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Blockchain, My Wallet, Second Password",
    slug = "blockchain-second",
    hashcat = [40040]
)]
pub struct BlockchainSecond {
    /// Payload
    #[field(role = salt, encoding = base64)]
    pub payload: Vec<u8>,
}

impl Parse for BlockchainSecond {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let payload = parse::decode_base64(input, 0)?;
        if payload.first() != Some(&b'b') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected a Blockchain second-password blob",
            ));
        }
        Ok(Self { payload })
    }
}

impl Render for BlockchainSecond {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::base64(&self.payload)
    }
}
