//! NTLM applied twice, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single NTLM applied twice digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "NTLM applied twice",
    slug = "ntlm-double",
    hashcat = [40080],
)]
pub struct NtlmDouble {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for NtlmDouble {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for NtlmDouble {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
