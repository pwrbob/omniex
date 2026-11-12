//! Radmin2, rendered as a bare hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Radmin2 password hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Radmin2",
    slug = "radmin2",
    hashcat = [9900],
    john = ["RAdmin"],
)]
pub struct Radmin2 {
    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Radmin2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let input = input.strip_prefix("$radmin2$").unwrap_or(input);
        Ok(Self {
            digest: parse::decode_hex_field::<16>(input, 0, "digest")?,
        })
    }
}

impl Render for Radmin2 {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            format!(
                "$radmin2${}",
                crate::format::hex(self.digest).to_uppercase()
            )
        } else {
            crate::format::hex(self.digest)
        }
    }
}
