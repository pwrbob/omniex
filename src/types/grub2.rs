//! GRUB 2 PBKDF2-SHA512 hashes, rendered as
//! `grub.pbkdf2.sha512.<iterations>.<salt>.<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// GRUB 2 PBKDF2-SHA512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "GRUB 2", slug = "grub2", hashcat = [40019])]
pub struct Grub2 {
    /// PBKDF2 iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// 64-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Grub2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "grub.pbkdf2.sha512.", 0)?;
        let fields = parse::split_fields(rest, '.', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid GRUB iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: parse::decode_hex(fields[1].0, fields[1].1)?,
            digest: parse::decode_hex_field::<64>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Grub2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "grub.pbkdf2.sha512.{}.{}.{}",
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(self.digest)
        )
    }
}
