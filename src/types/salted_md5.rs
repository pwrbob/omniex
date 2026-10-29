//! MD5 with a salt, rendered as `<digest>:<salt>` in lowercase hex.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MD5 with one salt.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Salted MD5",
    slug = "salted-md5",
    family = Md5,
    hashcat = [10, 20, 3800],
)]
pub struct SaltedMd5 {
    /// The 16-byte MD5 digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],

    /// Salt used by the attack mode.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
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

        let digest = parse::decode_hex_field::<16>(&input[..separator], 0, "digest")?;
        let salt = parse::decode_hex(&input[separator + 1..], separator + 1)?;

        Ok(Self { digest, salt })
    }
}

impl Render for SaltedMd5 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}:{}",
            crate::format::hex(self.digest),
            crate::format::hex(&self.salt)
        )
    }
}
