//! MD5 with two salts, rendered as `<digest>:<salt1>:<salt2>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 with two salts (the `salt1` value first in the string).
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MD5 (two salts)",
    slug = "md5-two-salts",
    hashcat = [3730, 31700, 32300, 33000],
    modes_fn = md5_two_salts_modes,
)]
pub struct Md5TwoSalts {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// First salt, serialized as ASCII.
    #[field(role = salt, encoding = ascii)]
    pub salt1: String,

    /// Second salt, serialized as ASCII.
    #[field(role = salt, encoding = ascii)]
    pub salt2: String,
}

pub fn md5_two_salts_modes(_value: &Md5TwoSalts) -> Vec<crate::Mode> {
    vec![
        crate::Mode::Hashcat(3730),
        crate::Mode::Hashcat(31700),
        crate::Mode::Hashcat(33000),
        crate::Mode::Hashcat(32300),
    ]
}

impl Parse for Md5TwoSalts {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, rest, rest_offset) = parse::split_once(input, ':', 0)?;
        let (salt1, salt2, _) = parse::split_once(rest, ':', rest_offset)?;

        if salt1.contains(':') || salt2.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                rest_offset,
                "salts must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 0, "digest")?,
            salt1: salt1.to_owned(),
            salt2: salt2.to_owned(),
        })
    }
}

impl Render for Md5TwoSalts {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            self.salt1,
            self.salt2
        )
    }
}
