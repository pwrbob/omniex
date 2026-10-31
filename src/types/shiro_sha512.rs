//! Apache Shiro SHA-512 hashes, rendered as
//! `$shiro1$SHA-512$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apache Shiro 1 SHA-512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Apache Shiro 1 SHA-512", slug = "shiro-sha512", hashcat = [40035])]
pub struct ShiroSha512 {
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

impl Parse for ShiroSha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$shiro1$SHA-512$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid Shiro iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: parse::decode_base64(fields[1].0, fields[1].1)?,
            digest: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for ShiroSha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$shiro1$SHA-512${}${}${}",
            self.iterations,
            crate::format::base64(&self.salt),
            crate::format::base64(&self.digest)
        )
    }
}
