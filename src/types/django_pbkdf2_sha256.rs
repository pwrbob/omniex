//! Django PBKDF2 SHA2-256, rendered as `pbkdf2_sha256$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Django PBKDF2 SHA2-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Django (PBKDF2-SHA256)",
    slug = "django-pbkdf2-sha256",
    hashcat = [40022],
)]
pub struct DjangoPbkdf2Sha256 {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Digest
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for DjangoPbkdf2Sha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "pbkdf2_sha256$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (digest, digest_offset) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                14 + iterations_offset,
                "invalid Django iteration count",
            )
        })?;
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                14 + salt_offset,
                "Django salt must not be empty",
            ));
        }
        let digest = parse::decode_base64(digest, 14 + digest_offset)?;
        if digest.len() != 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                14 + digest_offset,
                "Django digest must be 32 bytes",
            ));
        }

        Ok(Self {
            iterations,
            salt: salt.to_owned(),
            digest,
        })
    }
}

impl Render for DjangoPbkdf2Sha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "pbkdf2_sha256${}${}${}",
            self.iterations,
            self.salt,
            crate::format::base64(&self.digest)
        )
    }
}
