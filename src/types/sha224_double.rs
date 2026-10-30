//! SHA2-224 applied twice, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single SHA2-224 applied twice digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA2-224 applied twice",
    slug = "sha224-double",
    hashcat = [40076],
)]
pub struct Sha224Double {
    /// The 28-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 28],
}

impl Parse for Sha224Double {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<28>(input, 0, "digest")?,
        })
    }
}

impl Render for Sha224Double {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
