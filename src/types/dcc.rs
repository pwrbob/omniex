//! Domain Cached Credentials, rendered as `<digest>:<username>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MS Cache (Domain Cached Credentials) hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Domain Cached Credentials",
    slug = "dcc",
    hashcat = [1100, 31500],
    modes_fn = dcc_modes,
)]
pub struct Dcc {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// User name, serialized as ASCII.
    #[field(role = username, encoding = ascii)]
    pub username: String,
}

pub fn dcc_modes(value: &Dcc) -> Vec<crate::Mode> {
    if value.username.chars().count() > 256 {
        return Vec::new();
    }

    Dcc::DESCRIPTOR.all_modes.to_vec()
}

impl Parse for Dcc {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let Some(separator) = input.find(':') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `:` between digest and username",
            ));
        };

        let username = &input[separator + 1..];
        if let Some(offset) = username.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1 + offset,
                "username must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(&input[..separator], 0, "digest")?,
            username: username.to_owned(),
        })
    }
}

impl Render for Dcc {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.username)
    }
}
