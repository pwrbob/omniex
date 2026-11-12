//! NetIQ SSPR PBKDF2-HMAC-SHA1, rendered as `$pbkdf2-hmac-sha1$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR PBKDF2-HMAC-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (PBKDF2WithHmacSHA1)",
    slug = "sspr-pbkdf2-sha1",
    hashcat = [40064],
)]
pub struct SsprPbkdf2Sha1 {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Decimal salt text
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 20-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for SsprPbkdf2Sha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-hmac-sha1$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    17,
                    "invalid SSPR iteration count",
                )
            })?,
            salt: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<20>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for SsprPbkdf2Sha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pbkdf2-hmac-sha1${}${}${}",
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
