//! Umbraco HMAC-SHA1, rendered as a base64 digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Umbraco HMAC-SHA1 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Umbraco HMAC-SHA1",
    slug = "umbraco-hmac-sha1",
    hashcat = [24800],
)]
pub struct UmbracoHmacSha1 {
    /// The 20-byte digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 20],
}

impl Parse for UmbracoHmacSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let bytes = parse::decode_base64(input, 0)?;
        let digest = bytes.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "Umbraco digest must be 20 bytes",
            )
        })?;
        Ok(Self { digest })
    }
}

impl Render for UmbracoHmacSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::base64(self.digest)
    }
}
