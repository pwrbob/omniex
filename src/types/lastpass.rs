//! LastPass, rendered as `<digest>:<iterations>:<username>:<hash>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LastPass master password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LastPass",
    slug = "lastpass",
    hashcat = [6800],
)]
pub struct Lastpass {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Account username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// The 16-byte verification hash.
    #[field(role = other, encoding = hex)]
    pub hash: [u8; 16],
}

impl Parse for Lastpass {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 4)?;
        Ok(Self {
            digest: parse::decode_hex_field::<16>(fields[0].0, fields[0].1, "digest")?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid LastPass iteration count",
                )
            })?,
            username: fields[2].0.to_owned(),
            hash: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "hash")?,
        })
    }
}

impl Render for Lastpass {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}:{}",
            crate::format::hex(self.digest),
            self.iterations,
            self.username,
            crate::format::hex(self.hash)
        )
    }
}
