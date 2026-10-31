//! Apple File System volume hashes, rendered as
//! `$fvde$2$16$<salt>$<iterations>$<wrapped key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apple File System volume hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Apple File System (APFS)", slug = "apfs", hashcat = [18300])]
pub struct Apfs {
    /// Core Data primary key, always `2`.
    #[field(role = other, encoding = decimal)]
    pub primary_key: u32,

    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Forty-byte wrapped key.
    #[field(role = ciphertext, encoding = hex)]
    pub wrapped_key: [u8; 40],
}

impl Parse for Apfs {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$fvde$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        let primary_key = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid APFS primary key",
            )
        })?;
        let iterations = fields[3].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[3].1,
                "invalid APFS iteration count",
            )
        })?;
        Ok(Self {
            primary_key,
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            iterations,
            wrapped_key: parse::decode_hex_field::<40>(fields[4].0, fields[4].1, "wrapped key")?,
        })
    }
}

impl Render for Apfs {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$fvde${}$16${}${}${}",
            self.primary_key,
            crate::format::hex(self.salt),
            self.iterations,
            crate::format::hex(self.wrapped_key)
        )
    }
}
