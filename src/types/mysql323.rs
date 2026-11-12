//! MySQL323, rendered as 16 hexadecimal digits.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MySQL323 password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "MySQL323",
    slug = "mysql323",
    hashcat = [200],
    john = ["mysql"],
)]
pub struct Mysql323 {
    /// 8-byte MySQL323 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Mysql323 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        Ok(Self {
            digest: parse::decode_hex_field::<8>(input, 0, "digest")?,
        })
    }
}

impl Render for Mysql323 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest)
    }
}
