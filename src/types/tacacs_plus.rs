//! TACACS+, rendered as `$tacacs-plus$<version>$<salt>$<key>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// TACACS+ hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "TACACS+",
    slug = "tacacs-plus",
    hashcat = [16100],
    john = ["tacacs-plus"],
)]
pub struct TacacsPlus {
    /// Protocol version byte.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal session key.
    #[field(role = key, encoding = hex)]
    pub key: Vec<u8>,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for TacacsPlus {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$tacacs-plus$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        let (version, version_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (key, key_offset) = fields[2];
        let (digest, digest_offset) = fields[3];
        Ok(Self {
            version: version.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    13 + version_offset,
                    "invalid TACACS+ version",
                )
            })?,
            salt: parse::decode_hex(salt, 13 + salt_offset)?,
            key: parse::decode_hex(key, 13 + key_offset)?,
            digest: parse::decode_hex(digest, 13 + digest_offset)?,
        })
    }
}

impl Render for TacacsPlus {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$tacacs-plus${}${}${}${}",
            self.version,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.key),
            crate::format::hex(&self.digest)
        )
    }
}
