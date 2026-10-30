//! SHA2-512 with an ASCII salt, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA2-512 with one ASCII salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted SHA2-512",
    slug = "salted-sha512",
    hashcat = [1710, 1720, 1730, 1740],
    modes_fn = salted_sha512_modes,
)]
pub struct SaltedSha512 {
    /// The 64-byte SHA2-512 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

pub fn salted_sha512_modes(value: &SaltedSha512) -> Vec<crate::Mode> {
    let length = value.salt.len();

    SaltedSha512::DESCRIPTOR
        .all_modes
        .iter()
        .copied()
        .filter(|mode| match mode {
            crate::Mode::Hashcat(1730 | 1740) => length <= 27,
            crate::Mode::Hashcat(1710 | 1720) => length <= 256,
            _ => false,
        })
        .collect()
}

impl Parse for SaltedSha512 {
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
            digest: parse::decode_hex_field::<64>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for SaltedSha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
