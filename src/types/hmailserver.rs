//! hMailServer, rendered as `<salt><digest>` in hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// hMailServer password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "hMailServer",
    slug = "hmailserver",
    hashcat = [1421],
    john = ["hMailServer"],
)]
pub struct HmailServer {
    /// The 6-character salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: [u8; 6],

    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for HmailServer {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if input.len() != 70 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "hMailServer hash must contain a 6-character salt and 64 hex digits",
            ));
        }

        Ok(Self {
            salt: input.as_bytes()[..6].try_into().expect("6-byte salt"),
            digest: parse::decode_hex_field::<32>(&input[6..], 6, "digest")?,
        })
    }
}

impl Render for HmailServer {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&self.salt),
            crate::format::hex(self.digest)
        )
    }
}
