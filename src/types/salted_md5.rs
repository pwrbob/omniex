//! MD5 with a salt, rendered as `<digest>:<salt>` with an ASCII salt.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 with one salt.
///
/// This covers the hashcat modes that share the `<digest>:<salt>` string and
/// an ASCII salt. The key-derivation order and password encoding are attack
/// variants, not different types.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted MD5",
    slug = "salted-md5",
    hashcat = [10, 11, 12, 20, 21, 23, 24, 30, 40, 2611, 2630, 2711, 2811, 3610, 3710, 3800, 3910, 4010, 4110, 4410, 4420, 4430],
    modes_fn = salted_md5_modes,
)]
pub struct SaltedMd5 {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for SaltedMd5 {
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

        let digest = parse::decode_hex_field::<16>(&input[..separator], 0, "digest")?;

        Ok(Self {
            digest,
            salt: salt.to_owned(),
        })
    }
}

pub fn salted_md5_modes(value: &SaltedMd5) -> Vec<crate::Mode> {
    let length = value.salt.chars().count();
    let hex_salt = value.salt.bytes().all(|byte| byte.is_ascii_hexdigit());

    SaltedMd5::DESCRIPTOR
        .all_modes
        .iter()
        .copied()
        .filter(|mode| match mode {
            crate::Mode::Hashcat(11) => length == 32,
            crate::Mode::Hashcat(12) => length <= 32,
            crate::Mode::Hashcat(21 | 24) => length == 2 && hex_salt,
            crate::Mode::Hashcat(23) => length <= 247,
            crate::Mode::Hashcat(30 | 40) => length <= 27,
            crate::Mode::Hashcat(2611 | 3610 | 3710) => length <= 223,
            crate::Mode::Hashcat(2711) => length == 30,
            crate::Mode::Hashcat(2630 | 2811 | 3910 | 4010 | 4110 | 4410 | 4420 | 4430) => {
                length <= 256
            }
            crate::Mode::Hashcat(10 | 20 | 3800) => length <= 256,
            _ => false,
        })
        .collect()
}

impl Render for SaltedMd5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
