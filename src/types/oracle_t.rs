//! Oracle T type hashes, rendered as a bare 160-digit hexadecimal digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Oracle 12+ T type hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Oracle T: Type", slug = "oracle-t", hashcat = [40036])]
pub struct OracleT {
    /// Eighty-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 80],
}

impl Parse for OracleT {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        Ok(Self {
            digest: parse::decode_hex_field::<80>(input, 0, "digest")?,
        })
    }
}

impl Render for OracleT {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        crate::format::hex(self.digest).to_uppercase()
    }
}
