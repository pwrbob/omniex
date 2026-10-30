//! MD5 of MD5 salt and MD5 password, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 of MD5 salt and MD5 password values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MD5 of MD5 salt and MD5 password",
    slug = "md5-double-salt-md5",
    hashcat = [30500],
)]
pub struct Md5DoubleSaltMd5 {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for Md5DoubleSaltMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "salt must not contain `:`",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for Md5DoubleSaltMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
