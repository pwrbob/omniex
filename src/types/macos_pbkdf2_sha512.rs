//! macOS v10.8+ PBKDF2-SHA512, rendered as `$ml$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// macOS v10.8+ PBKDF2-SHA512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "macOS v10.8+ (PBKDF2-SHA512)",
    slug = "macos-pbkdf2-sha512",
    hashcat = [40018],
)]
pub struct MacosPbkdf2Sha512 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for MacosPbkdf2Sha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$ml$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let (iterations, iterations_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (digest, digest_offset) = fields[2];

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                4 + iterations_offset,
                "invalid macOS iteration count",
            )
        })?;
        let salt = parse::decode_hex(salt, 4 + salt_offset)?;
        if salt.len() != 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                4 + salt_offset,
                "macOS salt must be 32 bytes",
            ));
        }
        let digest = parse::decode_hex(digest, 4 + digest_offset)?;
        if digest.len() != 64 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                4 + digest_offset,
                "macOS digest must be 64 bytes",
            ));
        }

        Ok(Self {
            iterations,
            salt,
            digest,
        })
    }
}

impl Render for MacosPbkdf2Sha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ml${}${}${}",
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.digest)
        )
    }
}
