//! PeopleSoft SHA-1, rendered as standard base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PeopleSoft SHA-1 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "PeopleSoft SHA1",
    slug = "peoplesoft-sha1",
    hashcat = [133],
)]
pub struct PeoplesoftSha1 {
    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 20],
}

impl Parse for PeoplesoftSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let digest = parse::decode_base64(input, 0)?;
        digest
            .try_into()
            .map(|digest| Self { digest })
            .map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidLength,
                    0,
                    "PeopleSoft digest must decode to 20 bytes",
                )
            })
    }
}

impl Render for PeoplesoftSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        crate::format::base64(self.digest)
    }
}
