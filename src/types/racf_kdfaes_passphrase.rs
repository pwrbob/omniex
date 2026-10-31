//! RACF KDFAES passphrase hashes, rendered as
//! `$racf-kdfaes$*<user>*<salt>*<data>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RACF KDFAES passphrase hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RACF KDFAES Passphrase",
    slug = "racf-kdfaes-passphrase",
    hashcat = [37500]
)]
pub struct RacfKdfaesPassphrase {
    /// RACF user name.
    #[field(role = username, encoding = ascii)]
    pub user: String,

    /// KDF parameters in hexadecimal.
    #[field(role = other, encoding = ascii)]
    pub parameters: String,

    /// Sixteen-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for RacfKdfaesPassphrase {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$racf-kdfaes$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            user: fields[0].0.to_owned(),
            parameters: fields[1].0.to_owned(),
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            digest: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for RacfKdfaesPassphrase {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$racf-kdfaes$*{}*{}*{}*{}",
            self.user,
            self.parameters,
            crate::format::hex(self.salt).to_uppercase(),
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
