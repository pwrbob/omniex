//! Zed hashes, rendered as `$zed$<version>$<cipher>$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Zed hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Zed", slug = "zed", hashcat = [], john = ["zed"])]
pub struct Zed {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Cipher identifier.
    #[field(role = other, encoding = decimal)]
    pub cipher: u8,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Eight-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// Eight-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Zed {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$zed$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid Zed version")
            })?,
            cipher: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 7, "invalid Zed cipher")
            })?,
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid Zed iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "salt")?,
            digest: parse::decode_hex_field::<8>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for Zed {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$zed${}${}${}${}${}",
            self.version,
            self.cipher,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
