//! Mozilla key3.db, rendered as `$mozilla$*<cipher>*<salt>*<entry salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// Mozilla key3.db hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Mozilla key3.db",
    slug = "mozilla-key3",
    hashcat = [26000],
)]
pub struct MozillaKey3 {
    /// Cipher name.
    #[field(role = other, encoding = ascii)]
    pub cipher: String,

    /// Hexadecimal global salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Hexadecimal entry salt.
    #[field(role = salt, encoding = ascii)]
    pub entry_salt: String,

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for MozillaKey3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$mozilla$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            cipher: fields[0].0.to_owned(),
            salt: fields[1].0.to_owned(),
            entry_salt: fields[2].0.to_owned(),
            digest: parse::decode_hex_field::<16>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for MozillaKey3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$mozilla$*{}*{}*{}*{}",
            self.cipher,
            self.salt,
            self.entry_salt,
            crate::format::hex(self.digest)
        )
    }
}
