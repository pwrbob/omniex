//! RACF KDFAES, rendered as `$racf-kdfaes$*<user>*<salt>*<iv>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RACF KDFAES password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RACF KDFAES",
    slug = "racf-kdfaes",
    hashcat = [14200],
)]
pub struct RacfKdfaes {
    /// RACF user identifier.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Hexadecimal salt.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Hexadecimal IV.
    #[field(role = iv, encoding = hex)]
    pub iv: Vec<u8>,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for RacfKdfaes {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$racf-kdfaes$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            username: fields[0].0.to_owned(),
            salt: parse::decode_hex(fields[1].0, fields[1].1)?,
            iv: parse::decode_hex(fields[2].0, fields[2].1)?,
            digest: parse::decode_hex(fields[3].0, fields[3].1)?,
        })
    }
}

impl Render for RacfKdfaes {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$racf-kdfaes$*{}*{}*{}*{}",
            self.username,
            crate::format::hex(&self.salt).to_uppercase(),
            crate::format::hex(&self.iv).to_uppercase(),
            crate::format::hex(&self.digest).to_uppercase()
        )
    }
}
