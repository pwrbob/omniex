//! sm3crypt hashes, rendered as `$sm3$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// sm3crypt (Unix SM3) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "sm3crypt", slug = "sm3crypt", hashcat = [35100], john = ["sm3crypt"])]
pub struct Sm3crypt {
    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Base64 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for Sm3crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sm3$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 5)?;
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_base64(digest, digest_offset)?,
        })
    }
}

impl Render for Sm3crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$sm3${}${}",
            self.salt,
            crate::format::base64_no_pad(&self.digest)
        )
    }
}
