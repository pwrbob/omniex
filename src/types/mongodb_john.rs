//! John MongoDB hashes, rendered as `$mongodb$<version>$<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MongoDB hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MongoDB legacy",
    slug = "mongodb-legacy",
    hashcat = [],
    john = ["MongoDB"]
)]
pub struct MongodbJohn {
    /// Format version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// User name
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// 16-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for MongodbJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mongodb$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    9,
                    "invalid MongoDB version",
                )
            })?,
            username: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for MongodbJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mongodb${}${}${}",
            self.version,
            self.username,
            crate::format::hex(self.digest)
        )
    }
}
