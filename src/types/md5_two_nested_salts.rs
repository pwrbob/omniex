//! MD5 with two nested salts, rendered as `<digest>:<salt1>:<salt2>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 with two nested salts.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MD5 with two nested salts",
    slug = "md5-two-nested-salts",
    hashcat = [21310],
)]
pub struct Md5TwoNestedSalts {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// First salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt1: String,

    /// Second salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt2: String,
}

impl Parse for Md5TwoNestedSalts {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 3)?;
        let (digest, digest_offset) = fields[0];
        let (salt1, salt1_offset) = fields[1];
        let (salt2, _) = fields[2];

        if let Some(offset) = salt1.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt1_offset + offset,
                "first salt must not contain `:`",
            ));
        }
        if let Some(offset) = salt2.find(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt1_offset + salt1.len() + 1 + offset,
                "second salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
            salt1: salt1.to_owned(),
            salt2: salt2.to_owned(),
        })
    }
}

impl Render for Md5TwoNestedSalts {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            self.salt1,
            self.salt2
        )
    }
}
