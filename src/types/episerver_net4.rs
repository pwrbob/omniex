//! EPiServer 6.x (>= .NET 4), rendered as `$episerver$*1*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// EPiServer 6.x (>= .NET 4) password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "EPiServer (>= .NET 4)",
    slug = "episerver-net4",
    hashcat = [1441],
)]
pub struct EpiserverNet4 {
    /// Salt, base64 encoded in the hash string.
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// The 32-byte SHA-256 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 32],
}

impl Parse for EpiserverNet4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$episerver$*1*", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '*', 14)?;

        let salt = parse::decode_base64(salt, 14)?;
        let digest = parse::decode_base64(digest, digest_offset)?;

        if digest.len() != 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "EPiServer digest must decode to 32 bytes",
            ));
        }

        Ok(Self {
            salt,
            digest: digest.try_into().expect("32-byte digest"),
        })
    }
}

impl Render for EpiserverNet4 {
    fn render(&self, _opts: &RenderOptions) -> String {
        let digest = crate::format::base64(self.digest);
        format!(
            "$episerver$*1*{}*{}",
            crate::format::base64(&self.salt),
            digest.trim_end_matches('=')
        )
    }
}
