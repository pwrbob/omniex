//! SHA-1 with an ASCII salt, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA-1 with one ASCII salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted SHA1",
    slug = "salted-sha1",
    hashcat = [110, 120, 121, 130, 140, 4510, 4520, 4521, 4522, 4710, 4711, 4900, 5000],
    modes_fn = salted_sha1_modes,
)]
pub struct SaltedSha1 {
    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for SaltedSha1 {
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
            digest: parse::decode_hex_field::<20>(&input[..separator], 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

pub fn salted_sha1_modes(value: &SaltedSha1) -> Vec<crate::Mode> {
    let length = value.salt.len();

    SaltedSha1::DESCRIPTOR
        .all_modes
        .iter()
        .copied()
        .filter(|mode| match mode {
            crate::Mode::Hashcat(130 | 140) => length <= 27,
            crate::Mode::Hashcat(4521) => length == 32,
            crate::Mode::Hashcat(4522) => length == 12,
            crate::Mode::Hashcat(4711) => length == 8,
            crate::Mode::Hashcat(4900) => length <= 127,
            crate::Mode::Hashcat(5000) => length <= 256,
            crate::Mode::Hashcat(110 | 120 | 121 | 4510 | 4520 | 4710) => length <= 256,
            _ => false,
        })
        .collect()
}

impl Render for SaltedSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
