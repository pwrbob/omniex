//! SQLCipher, rendered as `SQLCIPHER*<version>*<iterations>*<salt>*<iv>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SQLCipher database hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SQLCipher",
    slug = "sqlcipher",
    hashcat = [24600],
)]
pub struct Sqlcipher {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 16-byte IV.
    #[field(role = iv, encoding = hex)]
    pub iv: [u8; 16],

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Sqlcipher {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "SQLCIPHER*", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    10,
                    "invalid SQLCipher version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid SQLCipher iteration count",
                )
            })?,
            salt: fields[2].0.to_owned(),
            iv: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "iv")?,
            digest: parse::decode_hex_field::<16>(fields[4].0, fields[4].1, "digest")?,
        })
    }
}

impl Render for Sqlcipher {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "SQLCIPHER*{}*{}*{}*{}*{}",
            self.version,
            self.iterations,
            self.salt,
            crate::format::hex(self.iv),
            crate::format::hex(self.digest)
        )
    }
}
