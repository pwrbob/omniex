//! Kremlin Encrypt 3.0 hashes, rendered as `$kgb$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Kremlin Encrypt 3.0 with NewDES hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kremlin Encrypt 3.0", slug = "kgb", hashcat = [32700])]
pub struct Kgb {
    /// 8-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for Kgb {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$kgb$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 5)?;
        Ok(Self {
            salt: parse::decode_hex_field::<8>(salt, 5, "salt")?,
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Kgb {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$kgb${}${}",
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
