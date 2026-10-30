//! SHA-1, rendered as a bare 40-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA-1 digest.
///
/// Modes that only change how the password is prepared still serialize as the
/// same bare digest, so they are modes of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA1",
    slug = "sha1",
    hashcat = [100, 170, 300, 4500, 4700],
    john = ["Raw-SHA1", "Raw-SHA1-Linkedin"],
)]
pub struct Sha1 {
    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Sha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<20>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
