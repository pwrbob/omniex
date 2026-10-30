//! QNX SHA2-512, rendered as `@S@<digest>@<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// QNX SHA2-512 shadow hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "QNX SHA2-512",
    slug = "qnx-sha512",
    hashcat = [19200],
)]
pub struct QnxSha512 {
    /// The 64-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Decimal salt used by the attack mode.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for QnxSha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "@S@", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, '@', 3)?;
        if salt.len() < 8 || salt.len() > 16 || !salt.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                3 + salt_offset,
                "QNX salt must be 8 to 16 hexadecimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<64>(digest, 3, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for QnxSha512 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("@S@{}@{}", crate::format::hex(self.digest), self.salt)
    }
}
