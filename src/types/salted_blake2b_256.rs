//! Salted BLAKE2b-256, rendered as `$BLAKE2$<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Salted BLAKE2b-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted BLAKE2b-256",
    slug = "salted-blake2b-256",
    hashcat = [34810, 34820],
    modes_fn = salted_blake2b_256_modes,
)]
pub struct SaltedBlake2b256 {
    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Salt bytes
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
}

pub fn salted_blake2b_256_modes(_value: &SaltedBlake2b256) -> Vec<crate::Mode> {
    vec![crate::Mode::Hashcat(34810), crate::Mode::Hashcat(34820)]
}

impl Parse for SaltedBlake2b256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$BLAKE2$", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, ':', 8)?;
        Ok(Self {
            digest: parse::decode_hex_field::<32>(digest, 8, "digest")?,
            salt: parse::decode_hex(salt, salt_offset)?,
        })
    }
}

impl Render for SaltedBlake2b256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$BLAKE2${}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.salt)
        )
    }
}
