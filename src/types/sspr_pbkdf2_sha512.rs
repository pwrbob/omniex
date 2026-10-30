//! NetIQ SSPR PBKDF2-HMAC-SHA512, rendered as `$pbkdf2-hmac-sha512$<iterations>.<salt>.<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR PBKDF2-HMAC-SHA512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (PBKDF2WithHmacSHA512)",
    slug = "sspr-pbkdf2-sha512",
    hashcat = [40066],
)]
pub struct SsprPbkdf2Sha512 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Decimal salt text.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 64-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for SsprPbkdf2Sha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-hmac-sha512$", 0)?;
        let fields = parse::split_fields(rest, '.', 3)?;
        Ok(Self {
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    19,
                    "invalid SSPR iteration count",
                )
            })?,
            salt: fields[1].0.to_owned(),
            digest: parse::decode_hex_field::<64>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for SsprPbkdf2Sha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pbkdf2-hmac-sha512${}.{}.{}",
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
