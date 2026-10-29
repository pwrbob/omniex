//! Django SHA-1, rendered as `sha1$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Django SHA-1 password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Django SHA1",
    slug = "django-sha1",
    hashcat = [124],
)]
pub struct DjangoSha1 {
    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for DjangoSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "sha1$", 0)?;
        let (salt, digest, offset) = parse::split_once(rest, '$', 5)?;

        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<20>(digest, offset, "digest")?,
        })
    }
}

impl Render for DjangoSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("sha1${}${}", self.salt, crate::format::hex(self.digest))
    }
}
