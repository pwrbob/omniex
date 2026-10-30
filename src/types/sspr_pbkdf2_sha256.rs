//! NetIQ SSPR PBKDF2-HMAC-SHA256, rendered as `$pbkdf2-sha256$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetIQ SSPR PBKDF2-HMAC-SHA256 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "NetIQ SSPR (PBKDF2WithHmacSHA256)",
    slug = "sspr-pbkdf2-sha256",
    hashcat = [40065],
)]
pub struct SsprPbkdf2Sha256 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Unpadded base64 salt text.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Unpadded base64 digest text.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for SsprPbkdf2Sha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$pbkdf2-sha256$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            iterations: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    14,
                    "invalid SSPR iteration count",
                )
            })?,
            salt: fields[1].0.to_owned(),
            digest: fields[2].0.to_owned(),
        })
    }
}

impl Render for SsprPbkdf2Sha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$pbkdf2-sha256${}${}${}",
            self.iterations, self.salt, self.digest
        )
    }
}
