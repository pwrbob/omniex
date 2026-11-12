//! bcrypt over HMAC-SHA256, rendered as
//! `$bcrypt-sha256$v=2,t=2b,r=<cost>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// bcrypt(HMAC-SHA256) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "bcrypt(HMAC-SHA256)",
    slug = "bcrypt-sha256-hmac",
    hashcat = [30601]
)]
pub struct BcryptSha256Hmac {
    /// bcrypt variant marker
    #[field(role = other, encoding = ascii)]
    pub variant: String,

    /// Cost parameter
    #[field(role = iterations, encoding = decimal)]
    pub cost: u32,

    /// Base64 salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for BcryptSha256Hmac {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bcrypt-sha256$v=2,t=", 0)?;
        let (variant, rest, rest_offset) = parse::split_once(rest, ',', 21)?;
        let rest = parse::strip_prefix(rest, "r=", rest_offset)?;
        let (cost, rest, rest_offset) = parse::split_once(rest, '$', rest_offset + 2)?;
        let (salt, digest, _) = parse::split_once(rest, '$', rest_offset)?;
        Ok(Self {
            variant: variant.to_owned(),
            cost: cost.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    rest_offset,
                    "invalid bcrypt cost",
                )
            })?,
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for BcryptSha256Hmac {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$bcrypt-sha256$v=2,t={},r={}${}${}",
            self.variant, self.cost, self.salt, self.digest
        )
    }
}
