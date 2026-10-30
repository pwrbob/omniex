//! Juniper/NetBSD sha1crypt, rendered as `$sha1$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Juniper/NetBSD sha1crypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Juniper/NetBSD sha1crypt",
    slug = "sha1crypt",
    hashcat = [40038],
)]
pub struct Sha1crypt {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Eight salt characters.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Twenty-eight digest characters.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Sha1crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$sha1$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (digest, digest_offset) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                6 + iterations_offset,
                "invalid sha1crypt iteration count",
            )
        })?;
        if salt.len() != 8 || !salt.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6 + salt_offset,
                "sha1crypt salt must be eight crypt characters",
            ));
        }
        if digest.len() != 28 || !digest.bytes().all(is_crypt_character) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6 + digest_offset,
                "sha1crypt digest must be 28 crypt characters",
            ));
        }

        Ok(Self {
            iterations,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Sha1crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$sha1${}${}${}", self.iterations, self.salt, self.digest)
    }
}

fn is_crypt_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')
}
