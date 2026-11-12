//! PBKDF1-SHA1, rendered as `PBKDF1:sha1:<iterations>:<salt>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF1-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PBKDF1-SHA1",
    slug = "pbkdf1-sha1",
    hashcat = [40070],
)]
pub struct Pbkdf1Sha1 {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// Digest
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Pbkdf1Sha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "PBKDF1:sha1:", 0)?;
        let fields = parse::split_fields(rest, ':', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (digest, digest_offset) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                12 + iterations_offset,
                "invalid PBKDF1 iteration count",
            )
        })?;
        let salt = parse::decode_base64(salt, 12 + salt_offset)?;
        let digest = parse::decode_base64(digest, 12 + digest_offset)?;
        if digest.len() != 20 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                12 + digest_offset,
                "PBKDF1-SHA1 digest must be 20 bytes",
            ));
        }

        Ok(Self {
            iterations,
            salt,
            digest,
        })
    }
}

impl Render for Pbkdf1Sha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "PBKDF1:sha1:{}:{}:{}",
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
