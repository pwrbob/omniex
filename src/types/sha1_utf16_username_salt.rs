//! SHA1 over a UTF-16LE username and salted password, rendered as `<digest>:<salt>:<username>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SHA1 with a salt and a UTF-16LE username.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SHA1 (UTF-16LE username, salted)",
    slug = "sha1-utf16-username-salt",
    hashcat = [29000],
)]
pub struct Sha1Utf16UsernameSalt {
    /// 20-byte SHA1 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],

    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Username bytes
    #[field(role = username, encoding = hex)]
    pub username: Vec<u8>,
}

impl Parse for Sha1Utf16UsernameSalt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let fields = parse::split_fields(input, ':', 3)?;
        let (digest, digest_offset) = fields[0];
        let (salt, salt_offset) = fields[1];
        let (username, username_offset) = fields[2];

        if salt.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "salt must not contain `:`",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<20>(digest, digest_offset, "digest")?,
            salt: salt.to_owned(),
            username: parse::decode_hex(username, username_offset)?,
        })
    }
}

impl Render for Sha1Utf16UsernameSalt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}:{}",
            crate::format::hex(self.digest),
            self.salt,
            crate::format::hex(&self.username)
        )
    }
}
