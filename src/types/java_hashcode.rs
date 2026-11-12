//! Java Object hashCode(), rendered as a bare 32-bit hexadecimal value.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Java Object hashCode() values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Java Object hashCode()",
    slug = "java-hashcode",
    hashcat = [18700],
)]
pub struct JavaHashcode {
    /// 4-byte hash value
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 4],
}

impl Parse for JavaHashcode {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<4>(input, 0, "digest")?,
        })
    }
}

impl Render for JavaHashcode {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
