//! MDC-2, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// A single MDC-2 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MDC-2",
    slug = "mdc2",
    hashcat = [40101],
    john = ["mdc2"],
)]
pub struct Mdc2 {
    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Mdc2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let input = input.strip_prefix("$mdc2$").unwrap_or(input);
        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Mdc2 {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            format!("$mdc2${}", crate::format::hex(self.digest))
        } else {
            crate::format::hex(self.digest)
        }
    }
}
