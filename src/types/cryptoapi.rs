//! Linux Kernel Crypto API, rendered as `$cryptoapi$<version>$<mode>$<salt>$<iv>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Linux Kernel Crypto API hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "Linux Kernel Crypto API (2.4)",
    slug = "linux-cryptoapi",
    hashcat = [14500],
)]
pub struct LinuxCryptoapi {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Cipher mode.
    #[field(role = other, encoding = decimal)]
    pub mode: u8,

    /// The 16-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// The 16-byte IV.
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for LinuxCryptoapi {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$cryptoapi$", 0)?;
        let fields = parse::split_fields(rest, '$', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    11,
                    "invalid cryptoapi version",
                )
            })?,
            mode: fields[1].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid cryptoapi mode",
                )
            })?,
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            iv: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "iv")?,
            digest: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for LinuxCryptoapi {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$cryptoapi${}${}${}${}${}",
            self.version,
            self.mode,
            crate::format::hex(self.salt),
            crate::format::hex(self.iv),
            crate::format::hex(self.digest)
        )
    }
}
