//! Mikrotik RouterOS hashes, rendered as `$mikrotik$<user>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Mikrotik RouterOS EC-SRP5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Mikrotik RouterOS", slug = "mikrotik", hashcat = [38000])]
pub struct Mikrotik {
    /// RouterOS user name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// 16-byte salt
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// 28-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 28],
}

impl Parse for Mikrotik {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mikrotik$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            salt: parse::decode_hex_field::<16>(fields[1].0, fields[1].1, "salt")?,
            digest: parse::decode_hex_field::<28>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Mikrotik {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mikrotik${}${}${}",
            self.username,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
