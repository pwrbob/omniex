//! Stargazer Stellar wallet, rendered as `$stellar$<salt>$<iv>$<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Stargazer Stellar wallet hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Stargazer Stellar Wallet XLM",
    slug = "stellar",
    hashcat = [25500],
)]
pub struct Stellar {
    /// Salt
    #[field(role = salt, encoding = base64)]
    pub salt: Vec<u8>,

    /// IV
    #[field(role = iv, encoding = base64)]
    pub iv: Vec<u8>,

    /// Ciphertext
    #[field(role = ciphertext, encoding = base64)]
    pub ciphertext: Vec<u8>,
}

impl Parse for Stellar {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$stellar$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            salt: parse::decode_base64(fields[0].0, fields[0].1)?,
            iv: parse::decode_base64(fields[1].0, fields[1].1)?,
            ciphertext: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for Stellar {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$stellar${}${}${}",
            crate::format::base64(&self.salt),
            crate::format::base64(&self.iv),
            crate::format::base64(&self.ciphertext)
        )
    }
}
