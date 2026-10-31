//! eCryptfs passphrase hashes, rendered as
//! `$ecryptfs$<version>$<flags>$<salt>$<signature>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// eCryptfs passphrase hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "eCryptfs", slug = "ecryptfs", hashcat = [12200])]
pub struct Ecryptfs {
    /// Format version, always `0`.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Feature flags, always `1`.
    #[field(role = other, encoding = decimal)]
    pub flags: u8,

    /// Eight-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 8],

    /// Eight-byte signature.
    #[field(role = digest, encoding = hex)]
    pub signature: [u8; 8],
}

impl Parse for Ecryptfs {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ecryptfs$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        let number = |field: (&str, usize), name: &str| -> Result<u8, ParseError> {
            field.0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    field.1,
                    format!("invalid eCryptfs {name}"),
                )
            })
        };
        Ok(Self {
            version: number(fields[0], "version")?,
            flags: number(fields[1], "flags")?,
            salt: parse::decode_hex_field::<8>(fields[2].0, fields[2].1, "salt")?,
            signature: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "signature")?,
        })
    }
}

impl Render for Ecryptfs {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ecryptfs${}${}${}${}",
            self.version,
            self.flags,
            crate::format::hex(self.salt),
            crate::format::hex(self.signature)
        )
    }
}
