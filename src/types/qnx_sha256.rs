//! QNX SHA2-256, rendered as `@s@<digest>@<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// QNX SHA2-256 shadow hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "QNX SHA2-256",
    slug = "qnx-sha256",
    hashcat = [19100],
)]
pub struct QnxSha256 {
    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],

    /// Decimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for QnxSha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "@s@", 0)?;
        let (digest, salt, salt_offset) = parse::split_once(rest, '@', 3)?;
        if salt.len() < 8 || salt.len() > 16 || !salt.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                3 + salt_offset,
                "QNX salt must be 8 to 16 hexadecimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<32>(digest, 3, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for QnxSha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("@s@{}@{}", crate::format::hex(self.digest), self.salt)
    }
}
