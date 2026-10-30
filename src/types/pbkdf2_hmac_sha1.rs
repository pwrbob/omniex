//! PBKDF2-HMAC-SHA1, rendered as `sha1:<iterations>:<salt>:<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// PBKDF2-HMAC-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "PBKDF2-HMAC-SHA1",
    slug = "pbkdf2-hmac-sha1",
    hashcat = [40032],
)]
pub struct Pbkdf2HmacSha1 {
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

impl Parse for Pbkdf2HmacSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "sha1:", 0)?;
        let fields = parse::split_fields(rest, ':', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (digest, digest_offset) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                "sha1:".len() + iterations_offset,
                "invalid PBKDF2 iteration count",
            )
        })?;
        let salt = parse::decode_base64(salt, "sha1:".len() + salt_offset)?;
        let digest = parse::decode_base64(digest, "sha1:".len() + digest_offset)?;
        if !(16..=64).contains(&digest.len()) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                "sha1:".len() + digest_offset,
                "PBKDF2-HMAC-SHA1 digest has the wrong length",
            ));
        }

        Ok(Self {
            iterations,
            salt,
            digest,
        })
    }
}

impl Render for Pbkdf2HmacSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "sha1:{}:{}:{}",
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
