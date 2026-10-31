//! MongoDB SCRAM-SHA-256 hashes, rendered as
//! `$mongodb-scram$*<version>*<user>*<iterations>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MongoDB server-key SCRAM-SHA-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MongoDB SCRAM-SHA-256",
    slug = "mongodb-scram-sha256",
    hashcat = [40053]
)]
pub struct MongodbScramSha256 {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Base64 user name.
    #[field(role = username, encoding = base64)]
    pub user: Vec<u8>,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Base64 salt.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for MongodbScramSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mongodb-scram$*", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        let version = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid MongoDB version",
            )
        })?;
        let iterations = fields[2].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[2].1,
                "invalid MongoDB iteration count",
            )
        })?;
        Ok(Self {
            version,
            user: parse::decode_base64(fields[1].0, fields[1].1)?,
            iterations,
            salt: parse::decode_base64(fields[3].0, fields[3].1)?,
            digest: parse::decode_base64(fields[4].0, fields[4].1)?,
        })
    }
}

impl Render for MongodbScramSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mongodb-scram$*{}*{}*{}*{}*{}",
            self.version,
            crate::format::base64(&self.user),
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
