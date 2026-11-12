//! Perl Mojolicious session cookie, rendered as `mojolicious=<payload>---<signature>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Perl Mojolicious session cookies.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Perl Mojolicious session cookie",
    slug = "mojolicious",
    hashcat = [16501],
)]
pub struct Mojolicious {
    /// Base64 pre-signature payload
    #[field(role = ciphertext, encoding = ascii)]
    pub payload: String,

    /// HMAC signature
    #[field(role = digest, encoding = hex)]
    pub signature: [u8; 32],
}

impl Parse for Mojolicious {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "mojolicious=", 0)?;
        let Some(separator) = rest.find("---") else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                rest.len(),
                "expected `---` before the Mojolicious signature",
            ));
        };
        let payload = &rest[..separator];
        if payload.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                12,
                "Mojolicious payload must not be empty",
            ));
        }
        let signature = &rest[separator + 3..];
        Ok(Self {
            payload: payload.to_owned(),
            signature: parse::decode_hex_field::<32>(signature, 15 + separator, "signature")?,
        })
    }
}

impl Render for Mojolicious {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "mojolicious={}---{}",
            self.payload,
            crate::format::hex(self.signature)
        )
    }
}
