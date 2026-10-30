//! AuthMe SHA2-256, rendered as `$SHA$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AuthMe SHA2-256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AuthMe SHA2-256",
    slug = "authme-sha256",
    hashcat = [20711],
)]
pub struct AuthMeSha256 {
    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for AuthMeSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$SHA$", 0)?;
        let fields = parse::split_fields(rest, '$', 2)?;
        let (salt, salt_offset) = fields[0];
        let (digest, digest_offset) = fields[1];

        if salt.contains('$') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "salt must not contain `$`",
            ));
        }

        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<32>(digest, 5 + digest_offset, "digest")?,
        })
    }
}

impl Render for AuthMeSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$SHA${}${}", self.salt, crate::format::hex(self.digest))
    }
}
