//! QNX MD5, rendered as `@m@<digest>@<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// QNX MD5 shadow hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "QNX MD5",
    slug = "qnx-md5",
    hashcat = [19000],
)]
pub struct QnxMd5 {
    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Decimal salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for QnxMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "@m@", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, '@', 3)?;
        if salt.len() < 8 || salt.len() > 16 || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                3 + salt_offset,
                "QNX salt must be 8 to 16 decimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<16>(digest, 3, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for QnxMd5 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("@m@{}@{}", crate::format::hex(self.digest), self.salt)
    }
}
