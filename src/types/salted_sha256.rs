//! SHA2-256 with an ASCII salt, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA2-256 with one ASCII salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted SHA2-256",
    slug = "salted-sha256",
    hashcat = [1410, 1420, 1430, 1440],
    modes_fn = salted_sha256_modes,
)]
pub struct SaltedSha256 {
    /// The 32-byte SHA2-256 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

pub fn salted_sha256_modes(value: &SaltedSha256) -> Vec<crate::Mode> {
    let length = value.salt.len();

    SaltedSha256::DESCRIPTOR
        .all_modes
        .iter()
        .copied()
        .filter(|mode| match mode {
            crate::Mode::Hashcat(1430 | 1440) => length <= 27,
            crate::Mode::Hashcat(1410 | 1420) => length <= 256,
            _ => false,
        })
        .collect()
}

impl Parse for SaltedSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let Some(separator) = input.find(':') else {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                input.len(),
                "expected `:` between digest and salt",
            ));
        };

        let salt = &input[separator + 1..];
        if let Some(offset) = salt.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                separator + 1 + offset,
                "salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<32>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for SaltedSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
