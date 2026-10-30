//! Web2py PBKDF2-SHA512, rendered as `pbkdf2(<iterations>,<keylen>,sha512)$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Web2py PBKDF2-SHA512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Web2py pbkdf2-sha512",
    slug = "web2py-pbkdf2-sha512",
    hashcat = [40050],
)]
pub struct Web2pyPbkdf2Sha512 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Derived key length in bytes.
    #[field(role = other, encoding = decimal)]
    pub key_length: u32,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for Web2pyPbkdf2Sha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "pbkdf2(", 0)?;
        let (parameters, rest, rest_offset) = parse::split_once(rest, ')', 7)?;
        let rest = parse::strip_prefix(rest, "$", 7 + rest_offset)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 8 + rest_offset)?;

        let mut parts = parameters.split(',');
        let iterations = parts.next().unwrap_or_default();
        let key_length = parts.next().unwrap_or_default();
        let algorithm = parts.next().unwrap_or_default();
        if parts.next().is_some() || algorithm != "sha512" {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                7,
                "expected pbkdf2(<iterations>,<keylen>,sha512)",
            ));
        }

        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                7,
                "invalid Web2py iteration count",
            )
        })?;
        let key_length = key_length.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                7,
                "invalid Web2py key length",
            )
        })?;
        if salt.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                8 + rest_offset,
                "Web2py salt must not be empty",
            ));
        }
        let digest = parse::decode_hex(digest, 8 + rest_offset + digest_offset)?;

        Ok(Self {
            iterations,
            key_length,
            salt: salt.to_owned(),
            digest,
        })
    }
}

impl Render for Web2pyPbkdf2Sha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "pbkdf2({},{},sha512)${}${}",
            self.iterations,
            self.key_length,
            self.salt,
            crate::format::hex(&self.digest)
        )
    }
}
