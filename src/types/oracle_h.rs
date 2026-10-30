//! Oracle 7+ `H:` hashes, rendered as `<digest>:<salt>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Oracle 7+ `H:` password hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Oracle H",
    slug = "oracle-h",
    hashcat = [3100],
)]
pub struct OracleH {
    /// The 8-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],

    /// Decimal salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,
}

impl Parse for OracleH {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let (digest, salt, salt_offset) = parse::split_once(input, ':', 0)?;
        if salt.is_empty() || !salt.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                salt_offset,
                "Oracle H salt must be decimal digits",
            ));
        }

        Ok(Self {
            digest: parse::decode_hex_field::<8>(digest, 0, "digest")?,
            salt: salt.to_owned(),
        })
    }
}

impl Render for OracleH {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", crate::format::hex(self.digest), self.salt)
    }
}
