//! SHA1 with two salts, rendered as `<digest>:<salt1>:<salt2>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA1 with two salts.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA1 with two salts",
    slug = "sha1-two-salts",
    hashcat = [19300],
)]
pub struct Sha1TwoSalts {
    /// The 20-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// First salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt1: String,

    /// Second salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt2: String,
}

impl Parse for Sha1TwoSalts {
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
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
            salt1: salt1.to_owned(),
            salt2: salt2.to_owned(),
        })
    }
}

impl Render for Sha1TwoSalts {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            self.salt1,
            self.salt2
        )
    }
}
