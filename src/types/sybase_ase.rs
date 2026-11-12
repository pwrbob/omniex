//! Sybase ASE, rendered as `0xc007<salt><digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Sybase ASE password hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Sybase ASE",
    slug = "sybase-ase",
    hashcat = [8000], john = ["SybaseASE"],
)]
pub struct SybaseAse {
    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 32-byte SHA2-256 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for SybaseAse {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "0x", 0)?;
        if rest.len() != 84 || !rest.starts_with("c007") {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Sybase ASE values are `0xc007` plus 80 hexadecimal digits",
            ));
        }
        Ok(Self {
            salt: parse::decode_hex_field::<8>(&rest[4..20], 6, "salt")?,
            digest: parse::decode_hex_field::<32>(&rest[20..], 22, "digest")?,
        })
    }
}

impl Render for SybaseAse {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "0xc007{}{}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
