//! FileZilla Server 0.9.55+, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// FileZilla Server SHA2-512 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "FileZilla Server >= 0.9.55",
    slug = "filezilla-server",
    hashcat = [15000],
)]
pub struct FilezillaServer {
    /// 64-byte SHA2-512 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],

    /// Decimal salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for FilezillaServer {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.len() != 64 || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "FileZilla salt must be 64 decimal digits",
            ));
        }
        Ok(Self {
            digest: parse::decode_hex_field::<64>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for FilezillaServer {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
