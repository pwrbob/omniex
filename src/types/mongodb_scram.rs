//! MongoDB ServerKey SCRAM, rendered as a `$mongodb-scram$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MongoDB SCRAM server-key hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MongoDB ServerKey SCRAM-SHA-1",
    slug = "mongodb-scram",
    hashcat = [24100],
)]
pub struct MongodbScram {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Base64 username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Base64-encoded salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64-encoded digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for MongodbScram {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mongodb-scram$*", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    16,
                    "invalid MongoDB SCRAM version",
                )
            })?,
            username: fields[1].0.to_owned(),
            iterations: fields[2].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[2].1,
                    "invalid MongoDB iteration count",
                )
            })?,
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
            digest: parse::decode_base64(fields[4].0, fields[4].1)?,
        })
    }
}

impl Render for MongodbScram {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mongodb-scram$*{}*{}*{}*{}*{}",
            self.version,
            self.username,
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
